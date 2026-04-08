import { CheckboxCard } from "@/components/checkbox-card/checkbox-card";
import { useProcessesQuery } from "@/services/processes";
import { Rule, useCreateRuleMutation, useRuleQuery, useUpdateRuleMutation } from "@/services/settings";
import { ActionIcon, Affix, Button, Fieldset, Group, Paper, Select, Stack, TextInput } from "@mantine/core";
import { useForm } from "@mantine/form";
import { getHotkeyHandler } from "@mantine/hooks";
import { showNotification } from "@mantine/notifications";
import { IconFolderOpen, IconRefresh, IconTrash } from "@tabler/icons-react";
import { useNavigate } from "@tanstack/react-router";
import { open } from "@tauri-apps/plugin-dialog";
import { random, snakeCase, uniqBy } from "lodash-es";
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
      ip_addresses: [],
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

  const ipAddresses = form.getValues().ip_addresses.map((item, index) => (
    <Group key={index + item} mt="xs">
      <TextInput
        placeholder="eg: 1.1.1.1 or 1.1.1.*"
        style={{ flex: 1 }}
        key={form.key(`ip_addresses.${index}`)}
        {...form.getInputProps(`ip_addresses.${index}`)}
      />

      <ActionIcon color="red" onClick={() => form.removeListItem("ip_addresses", index)}>
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

  const navigate = useNavigate();
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

    mutation(newRule)
      .then(() => {
        showNotification({
          title: "Success",
          message: ruleId ? "Rule updated successfully" : "Rule created successfully",
          color: "teal",
        });

        if (!ruleId) {
          navigate({ to: "/rules/edit/$ruleId", params: { ruleId: newRule.id } });
        }
      })
      .catch((error) => {
        showNotification({
          title: "Error",
          message: error.message || "An error occurred",
          color: "red",
        });
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
                  description="Press enter to add host"
                  placeholder="eg: example.com or *.example.com"
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
            <Fieldset legend="IP Addresses">
              <Stack gap="xs">
                <TextInput
                  description="Press enter to add IP address or range"
                  placeholder="eg: 1.1.1.1 or 1.1.1.*"
                  onKeyDown={getHotkeyHandler([
                    [
                      "Enter",
                      (event) => {
                        form.insertListItem("ip_addresses", event.target.value);
                        event.target.value = "";
                      },
                    ],
                  ])}
                />

                {ipAddresses}
              </Stack>
            </Fieldset>

            <Group grow>
              <CheckboxCard
                label="TLS/SNI Obfuscation"
                description="Modifies the TLS handshake structure to trick firewalls and unblock websites."
                {...form.getInputProps("sni_enabled", { type: "checkbox" })}
                key={form.key("sni_enabled")}
              />

              <CheckboxCard
                label="Transparent Secure DNS (DoH)"
                description="Automatically intercepts unencrypted DNS queries and resolves them securely over HTTPS."
                {...form.getInputProps("dns_enabled", { type: "checkbox" })}
                key={form.key("dns_enabled")}
              />
            </Group>
          </Stack>
        </Paper>

        <Affix position={{ bottom: 20, right: 20 }} withinPortal={false}>
          <Group justify="end">
            <Button type="submit">{ruleId ? "Update Rule" : "Create Rule"}</Button>
          </Group>
        </Affix>
      </Stack>
    </form>
  );
}
