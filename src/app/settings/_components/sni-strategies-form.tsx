import { CheckboxCard } from "@/app/_components/checkbox-card/checkbox-card";
import { useAppSettingsQuery, useDefaultAppSettingsQuery, useUpdateAppSettingsMutation } from "@/services/settings";
import { Affix, Badge, Button, Group, SimpleGrid, Stack, Text } from "@mantine/core";
import { useForm } from "@mantine/form";
import { IconRestore } from "@tabler/icons-react";
import { useEffect } from "react";

const AVAILABLE_STRATEGIES = [
  { name: "WrongChecksum", description: "Wrong TCP checksum with decoy packet" },
  { name: "FakeSni", description: "Fake SNI with decoy packet" },
  { name: "Overlap", description: "Low TTL overlapping packet" },
  { name: "IpFrag", description: "IP fragmentation splitting" },
  { name: "SniSplit", description: "SNI hostname splitting" },
  { name: "TcpFragment", description: "TCP fragmentation splitting" },
  { name: "FakePacket", description: "Corrupted decoy packets (before and after)" },
  { name: "Shuffle", description: "Reorder packets in sequence" },
];

const DEFAULT_STRATEGIES = Object.fromEntries(AVAILABLE_STRATEGIES.map((s) => [s.name, false]));

export function SniStrategiesForm() {
  const { data: settings } = useAppSettingsQuery();
  const { data: defaults } = useDefaultAppSettingsQuery();
  const updateMutation = useUpdateAppSettingsMutation();

  const form = useForm<Record<string, boolean>>({
    initialValues: DEFAULT_STRATEGIES,
  });

  useEffect(() => {
    if (settings) {
      const values = Object.fromEntries(
        AVAILABLE_STRATEGIES.map((s) => [s.name, settings.sni.strategies[s.name] === true]),
      );
      form.setValues(values);
      form.resetDirty(values);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings]);

  if (!settings) return null;

  const handleSubmit = form.onSubmit((values) => {
    updateMutation.mutate({
      ...settings,
      sni: { ...settings.sni, strategies: values },
    });
  });

  const handleRestoreDefaults = () => {
    if (!defaults) return;
    const values = Object.fromEntries(
      AVAILABLE_STRATEGIES.map((s) => [s.name, defaults.sni.strategies[s.name] === true]),
    );
    form.setValues(values);
  };

  const enabledCount = Object.values(form.values).filter(Boolean).length;

  return (
    <form id="sni-strategies-form" onSubmit={handleSubmit}>
      <Stack gap="md" pb={80}>
        <div>
          <Text fw={500} mb="sm">
            SNI Blocking Strategies
          </Text>
          <Text size="sm" c="dimmed" mb="md">
            Enable or disable each strategy for SNI blocking.
          </Text>
        </div>

        <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }} spacing="md">
          {AVAILABLE_STRATEGIES.map((strategy) => (
            <CheckboxCard
              key={strategy.name}
              radius="md"
              value={strategy.name}
              checked={form.values[strategy.name] === true}
              onChange={(checked) => form.setFieldValue(strategy.name, checked)}
              p="md"
              label={strategy.name}
              description={strategy.description}
            />
          ))}
        </SimpleGrid>

        <Badge leftSection="✓" variant="filled">
          {enabledCount} of {AVAILABLE_STRATEGIES.length} enabled
        </Badge>
      </Stack>

      <Affix position={{ bottom: 20, right: 20 }}>
        <Group gap="sm">
          <Button
            variant="default"
            disabled={!defaults}
            leftSection={<IconRestore size={16} />}
            onClick={handleRestoreDefaults}
          >
            Restore Defaults
          </Button>
          <Button
            form="sni-strategies-form"
            type="submit"
            loading={updateMutation.isPending}
            disabled={!form.isDirty()}
          >
            Save Changes
          </Button>
        </Group>
      </Affix>
    </form>
  );
}
