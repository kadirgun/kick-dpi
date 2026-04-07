"use client";

import { useProcessesQuery } from "@/services/processes";
import { Rule, useCreateRuleMutation, useRuleQuery, useUpdateRuleMutation } from "@/services/settings";
import { ActionIcon, Button, Checkbox, Fieldset, Group, Paper, Select, Stack, TextInput } from "@mantine/core";
import { useForm } from "@mantine/form";
import { getHotkeyHandler } from "@mantine/hooks";
import { showNotification } from "@mantine/notifications";
import { IconFolderOpen, IconRefresh, IconTrash } from "@tabler/icons-react";
import { open } from "@tauri-apps/plugin-dialog";
import { random, snakeCase, uniqBy } from "lodash-es";
import { useRouter } from "next/navigation";
import { useEffect, useMemo } from "react";

export type RuleFormProps = {
  ruleId?: string;
};

export function RuleForm({ ruleId }: RuleFormProps) {
  const { data: rule } = useRuleQuery(ruleId || "");

  const form = useForm<Rule>({
    mode: "uncontrolled",
    initialValues: {
      id: "",
      name: "",
      hosts: [],
      paths: [],
      dns_enabled: true,
      sni_enabled: true,
    },
  });

  useEffect(() => {
    if (!rule) return;
    form.setValues(rule);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rule]);

  const hosts = form.getValues().hosts.map((item, index) => (
    <Group key={index + item} mt="xs">
      <TextInput
        placeholder="example.com"
        style={{ flex: 1 }}
        key={form.key(`hosts.${index}`)}
        {...form.getInputProps(`hosts.${index}`)}
      />

      <ActionIcon color="red" onClick={() => form.removeListItem("hosts", index)}>
        <IconTrash size={16} />
      </ActionIcon>
    </Group>
  ));

  const paths = form.getValues().paths.map((item, index) => (
    <Group key={index + item} mt="xs">
      <TextInput
        placeholder="/path"
        style={{ flex: 1 }}
        key={form.key(`paths.${index}`)}
        {...form.getInputProps(`paths.${index}`)}
      />

      <ActionIcon color="red" onClick={() => form.removeListItem("paths", index)}>
        <IconTrash size={16} />
      </ActionIcon>
    </Group>
  ));

  const selectFolder = async () => {
    const selected = await open({
      multiple: true,
      directory: false,
    });

    if (!selected) return;

    selected.forEach((item) => {
      form.insertListItem("paths", item);
    });
  };

  const { data: processes, isPending: isProcessesPending, refetch: refetchProcesses } = useProcessesQuery();

  const processOptions = useMemo(() => {
    if (!processes) return [];

    return uniqBy(processes, "path").map((proc) => ({
      label: proc.path.split("\\").pop() || proc.path,
      value: proc.path,
    }));
  }, [processes]);

  const router = useRouter();
  const { mutateAsync: createRule } = useCreateRuleMutation();
  const { mutateAsync: updateRule } = useUpdateRuleMutation();
  const handleSubmit = async (values: Rule) => {
    const newRule: Rule = {
      ...values,
    };

    if (!ruleId) {
      newRule.id = `rule-${snakeCase(values.name)}-${random(1000000, 9999999)}`;
    }

    const mutation = ruleId ? updateRule : createRule;

    mutation(newRule).then(() => {
      showNotification({
        title: "Success",
        message: ruleId ? "Rule updated successfully" : "Rule created successfully",
        color: "teal",
      });

      if (!ruleId) {
        router.push(`/rules/edit?ruleId=${newRule.id}`);
      }
    });
  };

  return (
    <form onSubmit={form.onSubmit(handleSubmit)}>
      <Stack pb={65}>
        <Paper withBorder p="md">
          <Stack>
            <TextInput label="Rule Name" placeholder="Enter rule name" {...form.getInputProps("name")} />
            <Fieldset legend="Paths">
              <Stack gap="xs">
                <Group grow>
                  <TextInput
                    placeholder="Select file to load paths"
                    rightSection={
                      <ActionIcon onClick={selectFolder} variant="transparent" color="gray">
                        <IconFolderOpen size={16} />
                      </ActionIcon>
                    }
                  />
                  <Select
                    loading={isProcessesPending}
                    searchable
                    placeholder="Select process to load paths"
                    data={processOptions}
                    value={null}
                    onChange={(value) => {
                      if (!value) return;
                      form.insertListItem("paths", value);
                    }}
                    leftSection={
                      <ActionIcon variant="transparent" color="gray" onClick={() => refetchProcesses()}>
                        <IconRefresh size={16} />
                      </ActionIcon>
                    }
                  />
                </Group>

                {paths}
              </Stack>
            </Fieldset>
            <Fieldset legend="Hosts">
              <Stack gap="xs">
                <TextInput
                  placeholder="Press enter to add host"
                  onKeyDown={getHotkeyHandler([
                    [
                      "Enter",
                      (event) => {
                        form.insertListItem("hosts", event.target.value);
                        event.target.value = "";
                      },
                    ],
                  ])}
                />

                {hosts}
              </Stack>
            </Fieldset>

            <Checkbox
              label="Enable DNS"
              {...form.getInputProps("dns_enabled", { type: "checkbox" })}
              key={form.key("dns_enabled")}
            />
            <Checkbox
              label="Enable SNI"
              {...form.getInputProps("sni_enabled", { type: "checkbox" })}
              key={form.key("sni_enabled")}
            />
          </Stack>
        </Paper>

        <Paper p="md" pos="fixed" bottom={0} left={0} right={0}>
          <Group justify="end">
            <Button type="submit">{ruleId ? "Update Rule" : "Create Rule"}</Button>
          </Group>
        </Paper>
      </Stack>
    </form>
  );
}
