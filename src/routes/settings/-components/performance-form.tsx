import { useAppSettingsQuery, useDefaultAppSettingsQuery, useUpdateAppSettingsMutation } from "@/services/settings";
import { ActionIcon, Affix, Badge, Button, Group, NumberInput, SimpleGrid, Stack, Text } from "@mantine/core";
import { useForm } from "@mantine/form";
import { IconRestore } from "@tabler/icons-react";
import { useEffect } from "react";

export function PerformanceForm() {
  const { data: settings } = useAppSettingsQuery();
  const { data: defaults } = useDefaultAppSettingsQuery();
  const updateMutation = useUpdateAppSettingsMutation();

  const form = useForm({
    initialValues: {
      process_cache_refresh_ms: 5000,
      flow_cache_sleep_ms: 100,
      packet_buffer_size: 65535,
      dns_buffer_size: 65535,
      sni_buffer_size: 65535,
      connection_reset_buffer_kb: 4,
      wrong_checksum_decoy_ttl: 3,
      fake_sni_decoy_ttl: 3,
      overlap_decoy_ttl: 3,
      ip_frag_first_payload_bytes: 8,
    },
  });

  useEffect(() => {
    if (settings) {
      const values = {
        process_cache_refresh_ms: settings.performance.process_cache_refresh_ms,
        flow_cache_sleep_ms: settings.performance.flow_cache_sleep_ms,
        packet_buffer_size: settings.performance.packet_buffer_size,
        dns_buffer_size: settings.performance.dns_buffer_size,
        sni_buffer_size: settings.performance.sni_buffer_size,
        connection_reset_buffer_kb: settings.performance.connection_reset_buffer_kb,
        wrong_checksum_decoy_ttl: settings.strategy_params.wrong_checksum_decoy_ttl,
        fake_sni_decoy_ttl: settings.strategy_params.fake_sni_decoy_ttl,
        overlap_decoy_ttl: settings.strategy_params.overlap_decoy_ttl,
        ip_frag_first_payload_bytes: settings.strategy_params.ip_frag_first_payload_bytes,
      };
      form.setValues(values);
      form.resetDirty(values);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings]);

  if (!settings) return null;

  const fieldRestoreIcon = (field: keyof typeof form.values, defaultValue: unknown) => {
    if (!defaults || form.values[field] === defaultValue) return undefined;
    return (
      <ActionIcon
        size="sm"
        variant="subtle"
        color="gray"
        title="Restore default"
        onClick={() => form.setFieldValue(field, defaultValue as never)}
      >
        <IconRestore size={14} />
      </ActionIcon>
    );
  };

  const handleRestoreDefaults = () => {
    if (!defaults) return;
    form.setValues({
      process_cache_refresh_ms: defaults.performance.process_cache_refresh_ms,
      flow_cache_sleep_ms: defaults.performance.flow_cache_sleep_ms,
      packet_buffer_size: defaults.performance.packet_buffer_size,
      dns_buffer_size: defaults.performance.dns_buffer_size,
      sni_buffer_size: defaults.performance.sni_buffer_size,
      connection_reset_buffer_kb: defaults.performance.connection_reset_buffer_kb,
      wrong_checksum_decoy_ttl: defaults.strategy_params.wrong_checksum_decoy_ttl,
      fake_sni_decoy_ttl: defaults.strategy_params.fake_sni_decoy_ttl,
      overlap_decoy_ttl: defaults.strategy_params.overlap_decoy_ttl,
      ip_frag_first_payload_bytes: defaults.strategy_params.ip_frag_first_payload_bytes,
    });
  };

  const handleSubmit = form.onSubmit((values) => {
    updateMutation.mutate({
      ...settings,
      performance: {
        process_cache_refresh_ms: Math.max(0, values.process_cache_refresh_ms),
        flow_cache_sleep_ms: Math.max(0, values.flow_cache_sleep_ms),
        packet_buffer_size: Math.max(0, values.packet_buffer_size),
        dns_buffer_size: Math.max(0, values.dns_buffer_size),
        sni_buffer_size: Math.max(0, values.sni_buffer_size),
        connection_reset_buffer_kb: Math.max(1, values.connection_reset_buffer_kb),
      },
      strategy_params: {
        wrong_checksum_decoy_ttl: Math.max(1, values.wrong_checksum_decoy_ttl),
        fake_sni_decoy_ttl: Math.max(1, values.fake_sni_decoy_ttl),
        overlap_decoy_ttl: Math.max(1, values.overlap_decoy_ttl),
        ip_frag_first_payload_bytes: Math.max(1, values.ip_frag_first_payload_bytes),
      },
    });
  });

  return (
    <form id="performance-form" onSubmit={handleSubmit}>
      <Stack gap="md" pb={80}>
        <div>
          <Text fw={500} mb="md">
            Process and Cache Settings
          </Text>
          <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md">
            <div>
              <NumberInput
                label="Process Cache Refresh (ms)"
                min={100}
                step={100}
                leftSection={fieldRestoreIcon(
                  "process_cache_refresh_ms",
                  defaults?.performance.process_cache_refresh_ms,
                )}
                leftSectionPointerEvents="all"
                {...form.getInputProps("process_cache_refresh_ms")}
              />
              <Text size="xs" c="dimmed" mt={4}>
                Frequency of process information refresh
              </Text>
            </div>

            <div>
              <NumberInput
                label="Flow Cache Interval (ms)"
                min={10}
                step={10}
                leftSection={fieldRestoreIcon("flow_cache_sleep_ms", defaults?.performance.flow_cache_sleep_ms)}
                leftSectionPointerEvents="all"
                {...form.getInputProps("flow_cache_sleep_ms")}
              />
              <Text size="xs" c="dimmed" mt={4}>
                Flow cache evaluation interval
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
                min={1024}
                step={1024}
                leftSection={fieldRestoreIcon("packet_buffer_size", defaults?.performance.packet_buffer_size)}
                leftSectionPointerEvents="all"
                {...form.getInputProps("packet_buffer_size")}
              />
              <Text size="xs" c="dimmed" mt={4}>
                Packet processing buffer (bytes)
              </Text>
            </div>

            <div>
              <NumberInput
                label="DNS Buffer Size"
                min={1024}
                step={1024}
                leftSection={fieldRestoreIcon("dns_buffer_size", defaults?.performance.dns_buffer_size)}
                leftSectionPointerEvents="all"
                {...form.getInputProps("dns_buffer_size")}
              />
              <Text size="xs" c="dimmed" mt={4}>
                DNS packet buffer (bytes)
              </Text>
            </div>

            <div>
              <NumberInput
                label="SNI Buffer Size"
                min={1024}
                step={1024}
                leftSection={fieldRestoreIcon("sni_buffer_size", defaults?.performance.sni_buffer_size)}
                leftSectionPointerEvents="all"
                {...form.getInputProps("sni_buffer_size")}
              />
              <Text size="xs" c="dimmed" mt={4}>
                SNI packet buffer (bytes)
              </Text>
            </div>

            <div>
              <NumberInput
                label="Connection Reset Buffer (KB)"
                min={1}
                step={1}
                leftSection={fieldRestoreIcon(
                  "connection_reset_buffer_kb",
                  defaults?.performance.connection_reset_buffer_kb,
                )}
                leftSectionPointerEvents="all"
                {...form.getInputProps("connection_reset_buffer_kb")}
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
                  min={1}
                  max={255}
                  leftSection={fieldRestoreIcon(
                    "wrong_checksum_decoy_ttl",
                    defaults?.strategy_params.wrong_checksum_decoy_ttl,
                  )}
                  leftSectionPointerEvents="all"
                  {...form.getInputProps("wrong_checksum_decoy_ttl")}
                />
                <Text size="xs" c="dimmed" mt={4}>
                  Wrong checksum decoy packet TTL
                </Text>
              </div>

              <div>
                <NumberInput
                  label="FakeSni Decoy TTL"
                  min={1}
                  max={255}
                  leftSection={fieldRestoreIcon("fake_sni_decoy_ttl", defaults?.strategy_params.fake_sni_decoy_ttl)}
                  leftSectionPointerEvents="all"
                  {...form.getInputProps("fake_sni_decoy_ttl")}
                />
                <Text size="xs" c="dimmed" mt={4}>
                  Fake SNI decoy packet TTL
                </Text>
              </div>

              <div>
                <NumberInput
                  label="Overlap Decoy TTL"
                  min={1}
                  max={255}
                  leftSection={fieldRestoreIcon("overlap_decoy_ttl", defaults?.strategy_params.overlap_decoy_ttl)}
                  leftSectionPointerEvents="all"
                  {...form.getInputProps("overlap_decoy_ttl")}
                />
                <Text size="xs" c="dimmed" mt={4}>
                  Overlap decoy packet TTL
                </Text>
              </div>

              <div>
                <NumberInput
                  label="IP Frag First Payload (Bytes)"
                  min={1}
                  max={1500}
                  leftSection={fieldRestoreIcon(
                    "ip_frag_first_payload_bytes",
                    defaults?.strategy_params.ip_frag_first_payload_bytes,
                  )}
                  leftSectionPointerEvents="all"
                  {...form.getInputProps("ip_frag_first_payload_bytes")}
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
            Total buffer: {form.values.packet_buffer_size + form.values.dns_buffer_size + form.values.sni_buffer_size}{" "}
            bytes
          </Badge>
        </Group>
      </Stack>

      <Affix position={{ bottom: 20, right: 20 }} withinPortal={false}>
        <Group gap="sm">
          <Button
            variant="default"
            disabled={!defaults}
            leftSection={<IconRestore size={16} />}
            onClick={handleRestoreDefaults}
          >
            Restore Defaults
          </Button>
          <Button form="performance-form" type="submit" loading={updateMutation.isPending} disabled={!form.isDirty()}>
            Save Changes
          </Button>
        </Group>
      </Affix>
    </form>
  );
}
