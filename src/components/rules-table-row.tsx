import { resetConnectionsForRules, useDeleteRuleMutation, type Rule } from "@/services/settings";
import { ActionIcon, Group, Table, ThemeIcon, Tooltip } from "@mantine/core";
import { IconCheck, IconEdit, IconNetworkOff, IconTrash, IconX } from "@tabler/icons-react";
import { Link } from "@tanstack/react-router";
import { useMemo } from "react";

export type RulesTableRowProps = {
  rule: Rule;
};

export function RulesTableRow({ rule }: RulesTableRowProps) {
  const simpleHosts = useMemo(() => {
    if (rule.hosts.length === 0) return "-";
    if (rule.hosts.length > 2) {
      return rule.hosts.slice(0, 2).join(", ") + `, +${rule.hosts.length - 2} more`;
    }

    return rule.hosts.join(", ");
  }, [rule.hosts]);

  const simplePaths = useMemo(() => {
    if (rule.paths.length === 0) return "-";
    const filenames = rule.paths.map((path) => {
      const parts = path.split(/[/\\]/);
      return parts[parts.length - 1];
    });

    if (filenames.length > 2) {
      return filenames.slice(0, 2).join(", ") + `, +${filenames.length - 2} more`;
    }

    return filenames.join(", ");
  }, [rule.paths]);

  const { mutateAsync: deleteRule, isPending } = useDeleteRuleMutation();

  const handleDelete = async () => {
    await deleteRule(rule.id);
  };

  return (
    <Table.Tr key={rule.name}>
      <Table.Td>{rule.name}</Table.Td>
      <Table.Td>{simpleHosts}</Table.Td>
      <Table.Td>{simplePaths}</Table.Td>
      <Table.Td>
        <ThemeIcon color={rule.dns_enabled ? "green" : "gray"} radius="xl" size="sm">
          {rule.dns_enabled ? <IconCheck size={14} /> : <IconX size={14} />}
        </ThemeIcon>
      </Table.Td>
      <Table.Td>
        <ThemeIcon color={rule.sni_enabled ? "green" : "gray"} radius="xl" size="sm">
          {rule.sni_enabled ? <IconCheck size={14} /> : <IconX size={14} />}
        </ThemeIcon>
      </Table.Td>
      <Table.Td>
        <Group gap="xs" justify="end">
          <Link to="/rules/edit/$ruleId" params={{ ruleId: rule.id }}>
            <ActionIcon color="blue" variant="light">
              <IconEdit size={14} />
            </ActionIcon>
          </Link>
          <Tooltip label="Reset connections matching this rule" withArrow>
            <ActionIcon
              color="orange"
              variant="light"
              onClick={() => {
                resetConnectionsForRules([rule.id]);
              }}
            >
              <IconNetworkOff size={14} />
            </ActionIcon>
          </Tooltip>
          <ActionIcon variant="light" color="red" onClick={handleDelete} loading={isPending}>
            <IconTrash size={14} />
          </ActionIcon>
        </Group>
      </Table.Td>
    </Table.Tr>
  );
}
