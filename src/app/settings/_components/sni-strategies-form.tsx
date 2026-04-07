"use client";

import { CheckboxCard } from "@/app/_components/checkbox-card/checkbox-card";
import { useAppSettingsQuery, useUpdateAppSettingsMutation } from "@/services/settings";
import { Badge, SimpleGrid, Stack, Text } from "@mantine/core";

const AVAILABLE_STRATEGIES = [
  { name: "WrongChecksum", description: "Wrong TCP checksum with decoy packet" },
  { name: "FakeSni", description: "Fake SNI with decoy packet" },
  { name: "Overlap", description: "Low TTL overlapping segment" },
  { name: "IpFrag", description: "IP fragmentation splitting" },
  { name: "SniSplit", description: "TLS layer splitting" },
  { name: "TcpFragment", description: "TCP fragmentation splitting" },
  { name: "FakePacket", description: "Fake handshake packet" },
  { name: "Shuffle", description: "Reorder packet sequence" },
];

export function SniStrategiesForm() {
  const { data: settings } = useAppSettingsQuery();
  const updateMutation = useUpdateAppSettingsMutation();

  if (!settings) return null;

  const toggleStrategy = (strategyName: string) => {
    const newStrategies = { ...settings.sni.strategies };
    newStrategies[strategyName] = !newStrategies[strategyName];
    updateMutation.mutate({
      ...settings,
      sni: { ...settings.sni, strategies: newStrategies },
    });
  };

  const enabledCount = Object.values(settings.sni.strategies).filter(Boolean).length;

  return (
    <Stack gap="md">
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
            checked={settings.sni.strategies[strategy.name] === true}
            onChange={() => toggleStrategy(strategy.name)}
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
  );
}
