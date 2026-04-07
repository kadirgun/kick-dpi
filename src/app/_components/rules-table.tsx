import { useSettingsQuery } from "@/services/settings";
import { Center, Table, Text } from "@mantine/core";
import { RulesTableRow } from "./rules-table-row";

export function RulesTable() {
  const { data: settings } = useSettingsQuery();

  return (
    <Table>
      <Table.Thead>
        <Table.Tr>
          <Table.Th>Name</Table.Th>
          <Table.Th>Hosts</Table.Th>
          <Table.Th>Paths</Table.Th>
          <Table.Th>DNS</Table.Th>
          <Table.Th>SNI</Table.Th>
          <Table.Th></Table.Th>
        </Table.Tr>
      </Table.Thead>
      <Table.Tbody>
        {settings?.rules.length === 0 && (
          <Table.Tr>
            <Table.Td colSpan={5}>
              <Center p="xl">
                <Text c="dimmed" size="sm" ta="center">
                  No rules configured yet.
                </Text>
              </Center>
            </Table.Td>
          </Table.Tr>
        )}

        {settings?.rules.map((rule) => (
          <RulesTableRow key={rule.id} rule={rule} />
        ))}
      </Table.Tbody>
    </Table>
  );
}
