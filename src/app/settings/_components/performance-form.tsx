"use client";

import { useAppSettingsQuery, useUpdateAppSettingsMutation } from "@/services/settings";
import { Alert, Badge, Group, NumberInput, SimpleGrid, Stack, Text } from "@mantine/core";
import { IconAlertCircle } from "@tabler/icons-react";

export function PerformanceForm() {
  const { data: settings } = useAppSettingsQuery();
  const updateMutation = useUpdateAppSettingsMutation();

  if (!settings) return null;

  const handlePerformanceChange = (field: keyof typeof settings.performance, value: number | string) => {
    const numValue = typeof value === "string" ? parseInt(value) || 0 : value;
    updateMutation.mutate({
      ...settings,
      performance: {
        ...settings.performance,
        [field]: field === "connection_reset_buffer_kb" ? Math.max(1, numValue) : Math.max(0, numValue),
      },
    });
  };

  const handleStrategyChange = (field: keyof typeof settings.strategy_params, value: number | string) => {
    const numValue = typeof value === "string" ? parseInt(value) || 0 : value;
    updateMutation.mutate({
      ...settings,
      strategy_params: {
        ...settings.strategy_params,
        [field]: Math.max(1, numValue),
      },
    });
  };

  return (
    <Stack gap="md">
      <Alert icon={<IconAlertCircle />} color="blue" title="Warning">
        Changes to performance settings may require restarting the application to take effect.
      </Alert>

      <div>
        <Text fw={500} mb="md">
          Process and Cache Settings
        </Text>
        <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md">
          <div>
            <NumberInput
              label="Process Cache Refresh (ms)"
              value={settings.performance.process_cache_refresh_ms}
              onChange={(val) => handlePerformanceChange("process_cache_refresh_ms", val)}
              min={100}
              step={100}
            />
            <Text size="xs" c="dimmed" mt={4}>
              Frequency of process information refresh
            </Text>
          </div>

          <div>
            <NumberInput
              label="Flow Cache Sleep (ms)"
              value={settings.performance.flow_cache_sleep_ms}
              onChange={(val) => handlePerformanceChange("flow_cache_sleep_ms", val)}
              min={10}
              step={10}
            />
            <Text size="xs" c="dimmed" mt={4}>
              Flow cache thread sleep duration
            </Text>
          </div>
        </SimpleGrid>
      </div>

      <div>
        <Text fw={500} mb="md">
          Buffer Sizes
        </Text>
        <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md">
          <div>
            <NumberInput
              label="Packet Buffer Size"
              value={settings.performance.packet_buffer_size}
              onChange={(val) => handlePerformanceChange("packet_buffer_size", val)}
              min={1024}
              step={1024}
            />
            <Text size="xs" c="dimmed" mt={4}>
              Packet processing buffer (bytes)
            </Text>
          </div>

          <div>
            <NumberInput
              label="DNS Buffer Size"
              value={settings.performance.dns_buffer_size}
              onChange={(val) => handlePerformanceChange("dns_buffer_size", val)}
              min={1024}
              step={1024}
            />
            <Text size="xs" c="dimmed" mt={4}>
              DNS packet buffer (bytes)
            </Text>
          </div>

          <div>
            <NumberInput
              label="SNI Buffer Size"
              value={settings.performance.sni_buffer_size}
              onChange={(val) => handlePerformanceChange("sni_buffer_size", val)}
              min={1024}
              step={1024}
            />
            <Text size="xs" c="dimmed" mt={4}>
              SNI packet buffer (bytes)
            </Text>
          </div>

          <div>
            <NumberInput
              label="Connection Reset Buffer (KB)"
              value={settings.performance.connection_reset_buffer_kb}
              onChange={(val) => handlePerformanceChange("connection_reset_buffer_kb", val)}
              min={1}
              step={1}
            />
            <Text size="xs" c="dimmed" mt={4}>
              Connection reset operation buffer
            </Text>
          </div>
        </SimpleGrid>
      </div>

      <div>
        <Text fw={500} mb="md">
          Strategy Parameters
        </Text>
        <Stack gap="md">
          <Text size="sm" c="dimmed">
            These settings are for advanced users. Be careful when changing default values.
          </Text>
          <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md">
            <div>
              <NumberInput
                label="WrongChecksum Decoy TTL"
                value={settings.strategy_params.wrong_checksum_decoy_ttl}
                onChange={(val) => handleStrategyChange("wrong_checksum_decoy_ttl", val)}
                min={1}
                max={255}
              />
              <Text size="xs" c="dimmed" mt={4}>
                Wrong checksum decoy packet TTL
              </Text>
            </div>

            <div>
              <NumberInput
                label="FakeSni Decoy TTL"
                value={settings.strategy_params.fake_sni_decoy_ttl}
                onChange={(val) => handleStrategyChange("fake_sni_decoy_ttl", val)}
                min={1}
                max={255}
              />
              <Text size="xs" c="dimmed" mt={4}>
                Fake SNI decoy packet TTL
              </Text>
            </div>

            <div>
              <NumberInput
                label="Overlap Decoy TTL"
                value={settings.strategy_params.overlap_decoy_ttl}
                onChange={(val) => handleStrategyChange("overlap_decoy_ttl", val)}
                min={1}
                max={255}
              />
              <Text size="xs" c="dimmed" mt={4}>
                Overlap decoy packet TTL
              </Text>
            </div>

            <div>
              <NumberInput
                label="IP Frag First Payload (Bytes)"
                value={settings.strategy_params.ip_frag_first_payload_bytes}
                onChange={(val) => handleStrategyChange("ip_frag_first_payload_bytes", val)}
                min={1}
                max={1500}
              />
              <Text size="xs" c="dimmed" mt={4}>
                IP fragmentation first payload byte count
              </Text>
            </div>
          </SimpleGrid>
        </Stack>
      </div>

      <Group>
        <Badge>
          Total buffer:{" "}
          {settings.performance.packet_buffer_size +
            settings.performance.dns_buffer_size +
            settings.performance.sni_buffer_size}{" "}
          bytes
        </Badge>
      </Group>
    </Stack>
  );
}
