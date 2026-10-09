import { CheckboxCard } from "@/components/checkbox-card/checkbox-card";
import { useAppSettingsQuery, useDefaultAppSettingsQuery, useUpdateAppSettingsMutation } from "@/services/settings";
import { Affix, Badge, Button, Group, NumberInput, Select, SimpleGrid, Stack, Text, TextInput } from "@mantine/core";
import { useForm } from "@mantine/form";
import { IconRestore } from "@tabler/icons-react";
import { useEffect } from "react";

const AVAILABLE_STRATEGIES = [
  { name: "FakeTlsFirst", description: "Fake ClientHello before the real one (badsum/badseq + low TTL)" },
  { name: "Split", description: "Split ClientHello at protocol-aware positions" },
  { name: "Disorder", description: "Send fragments out of order (reversed)" },
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

type StrategyFormValues = {
  [key: string]: boolean | string | number;
  quic_mode: "block" | "fake";
  split_positions: string;
  fake_tls_first_repeats: number;
  fake_tls_first_fooling: "badsum" | "badseq";
};

export function SniStrategiesForm() {
  const { data: settings } = useAppSettingsQuery();
  const { data: defaults } = useDefaultAppSettingsQuery();
  const updateMutation = useUpdateAppSettingsMutation();

  const form = useForm<StrategyFormValues>({
    initialValues: {
      ...DEFAULT_STRATEGIES as Record<string, boolean>,
      quic_mode: "block",
      split_positions: "1, sniext+1",
      fake_tls_first_repeats: 6,
      fake_tls_first_fooling: "badsum",
    },
  });

  useEffect(() => {
    if (settings) {
      const values: StrategyFormValues = {
        ...Object.fromEntries(
          AVAILABLE_STRATEGIES.map((s) => [s.name, settings.sni.strategies[s.name] === true]),
        ),
        quic_mode: settings.sni.quic_mode,
        split_positions: settings.strategy_params.split_positions.join(", "),
        fake_tls_first_repeats: settings.strategy_params.fake_tls_first_repeats,
        fake_tls_first_fooling: settings.strategy_params.fake_tls_first_fooling,
      };
      form.setValues(values);
      form.resetDirty(values);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings]);

  if (!settings) return null;

  const handleSubmit = form.onSubmit((values) => {
    const splitPositions = values.split_positions
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    updateMutation.mutate({
      ...settings,
      sni: {
        ...settings.sni,
        quic_mode: values.quic_mode,
        strategies: Object.fromEntries(
          AVAILABLE_STRATEGIES.map((s) => [s.name, values[s.name] === true]),
        ),
      },
      strategy_params: {
        ...settings.strategy_params,
        split_positions: splitPositions.length > 0 ? splitPositions : ["1", "sniext+1"],
        fake_tls_first_repeats: Math.max(1, Math.min(Number(values.fake_tls_first_repeats), 11)),
        fake_tls_first_fooling: values.fake_tls_first_fooling,
      },
    });
  });

  const handleRestoreDefaults = () => {
    if (!defaults) return;
    const values: StrategyFormValues = {
      ...Object.fromEntries(
        AVAILABLE_STRATEGIES.map((s) => [s.name, defaults.sni.strategies[s.name] === true]),
      ),
      quic_mode: defaults.sni.quic_mode,
      split_positions: defaults.strategy_params.split_positions.join(", "),
      fake_tls_first_repeats: defaults.strategy_params.fake_tls_first_repeats,
      fake_tls_first_fooling: defaults.strategy_params.fake_tls_first_fooling,
    };
    form.setValues(values);
  };

  const enabledCount = AVAILABLE_STRATEGIES.filter((s) => form.values[s.name] === true).length;

  return (
    <form id="sni-strategies-form" onSubmit={handleSubmit}>
      <Stack gap="md" pb={80}>
        <div>
          <Text fw={500} mb="sm">
            SNI Blocking Strategies
          </Text>
          <Text size="sm" c="dimmed" mb="md">
            Enable or disable each strategy for SNI blocking. The default set
            (FakeTlsFirst + Split) is verified to work against Türk Telekom.
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

        <div>
          <Select
            label="QUIC (UDP 443) Handling"
            data={[
              { value: "block", label: "Block QUIC — force TCP fallback" },
              { value: "fake", label: "Send fake QUIC Initials, then block" },
            ]}
            leftSectionPointerEvents="all"
            {...form.getInputProps("quic_mode")}
          />
          <Text size="xs" c="dimmed" mt={4}>
            Fake mode feeds the DPI appliance decoy Initials before dropping
            the real packet
          </Text>
        </div>

        <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="md">
          <div>
            <TextInput
              label="Split Positions"
              placeholder="1, sniext+1"
              leftSectionPointerEvents="all"
              {...form.getInputProps("split_positions")}
            />
            <Text size="xs" c="dimmed" mt={4}>
              zapret markers: 1, sniext+N, host, sld, midsld, endsld or a number
            </Text>
          </div>
          <div>
            <NumberInput
              label="Fake ClientHello Repeats"
              min={1}
              max={11}
              leftSectionPointerEvents="all"
              {...form.getInputProps("fake_tls_first_repeats")}
            />
            <Text size="xs" c="dimmed" mt={4}>
              Decoy copies sent before the real hello (1-11)
            </Text>
          </div>
          <div>
            <Select
              label="Fake Fooling Method"
              data={[
                { value: "badsum", label: "badsum (corrupt checksums)" },
                { value: "badseq", label: "badseq (shift TCP sequence)" },
              ]}
              leftSectionPointerEvents="all"
              {...form.getInputProps("fake_tls_first_fooling")}
            />
          </div>
        </SimpleGrid>
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
