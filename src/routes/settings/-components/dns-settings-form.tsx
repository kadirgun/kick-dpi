import {
  DnsSettings,
  useAppSettingsQuery,
  useDefaultAppSettingsQuery,
  useUpdateAppSettingsMutation,
} from "@/services/settings";
import { ActionIcon, Affix, Button, Checkbox, Group, NumberInput, Select, Stack, Text, TextInput } from "@mantine/core";
import { useForm } from "@mantine/form";
import { IconRestore } from "@tabler/icons-react";
import { useEffect } from "react";

const DNS_PROVIDERS = [
  { value: "Cloudflare", label: "Cloudflare (1.1.1.1)" },
  { value: "Quad9", label: "Quad9 (9.9.9.9)" },
  { value: "NextDNS", label: "NextDNS (45.90.28.1)" },
  { value: "Custom", label: "Custom DoH URL" },
];

export function DnsSettingsForm() {
  const { data: settings } = useAppSettingsQuery();
  const { data: defaults } = useDefaultAppSettingsQuery();
  const updateMutation = useUpdateAppSettingsMutation();

  const form = useForm({
    initialValues: {
      provider: "Cloudflare" as DnsSettings["provider"],
      custom_url: "",
      timeout_ms: 2000,
      fallback_enabled: false,
      fallback_servers: "",
    },
  });

  useEffect(() => {
    if (settings) {
      const values = {
        provider: settings.dns.provider,
        custom_url: settings.dns.custom_url || "",
        timeout_ms: settings.dns.timeout_ms,
        fallback_enabled: settings.dns.fallback_enabled,
        fallback_servers: settings.dns.fallback_servers.join(", "),
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
      provider: defaults.dns.provider as DnsSettings["provider"],
      custom_url: defaults.dns.custom_url || "",
      timeout_ms: defaults.dns.timeout_ms,
      fallback_enabled: defaults.dns.fallback_enabled,
      fallback_servers: defaults.dns.fallback_servers.join(", "),
    });
  };

  const handleSubmit = form.onSubmit((values) => {
    const servers = values.fallback_servers
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    updateMutation.mutate({
      ...settings,
      dns: {
        provider: values.provider,
        custom_url: values.provider === "Custom" ? values.custom_url : undefined,
        timeout_ms: Math.max(500, Math.min(values.timeout_ms, 10000)),
        fallback_enabled: values.fallback_enabled,
        fallback_servers: servers,
      },
    });
  });

  return (
    <form id="dns-settings-form" onSubmit={handleSubmit}>
      <Stack gap="md" pb={80}>
        <div>
          <Select
            label="DNS Provider"
            placeholder="Select a provider"
            data={DNS_PROVIDERS}
            leftSection={fieldRestoreIcon("provider", defaults?.dns.provider)}
            leftSectionPointerEvents="all"
            {...form.getInputProps("provider")}
          />
          <Text size="xs" c="dimmed" mt={4}>
            Choose a DoH (DNS over HTTPS) provider
          </Text>
        </div>

        {form.values.provider === "Custom" && (
          <div>
            <TextInput
              label="Custom DoH URL"
              placeholder="https://dns.example.com/dns-query"
              leftSection={fieldRestoreIcon("custom_url", defaults?.dns.custom_url || "")}
              leftSectionPointerEvents="all"
              {...form.getInputProps("custom_url")}
            />
            <Text size="xs" c="dimmed" mt={4}>
              Enter the custom DoH endpoint URL
            </Text>
          </div>
        )}

        <div>
          <NumberInput
            label="DNS Timeout (ms)"
            placeholder="2000"
            min={500}
            max={10000}
            step={100}
            leftSection={fieldRestoreIcon("timeout_ms", defaults?.dns.timeout_ms)}
            leftSectionPointerEvents="all"
            {...form.getInputProps("timeout_ms")}
          />
          <Text size="xs" c="dimmed" mt={4}>
            DoH request timeout duration (500-10000 ms)
          </Text>
        </div>

        <Checkbox
          label="Enable Fallback DNS"
          description="Use traditional DNS servers if DoH fails"
          {...form.getInputProps("fallback_enabled", { type: "checkbox" })}
        />

        {form.values.fallback_enabled && (
          <div>
            <TextInput
              label="Fallback DNS Servers"
              placeholder="8.8.8.8, 8.8.4.4"
              leftSection={fieldRestoreIcon("fallback_servers", defaults?.dns.fallback_servers.join(", ") ?? "")}
              leftSectionPointerEvents="all"
              {...form.getInputProps("fallback_servers")}
            />
            <Text size="xs" c="dimmed" mt={4}>
              Comma-separated IP addresses (e.g. 8.8.8.8, 8.8.4.4)
            </Text>
          </div>
        )}
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
          <Button form="dns-settings-form" type="submit" loading={updateMutation.isPending} disabled={!form.isDirty()}>
            Save Changes
          </Button>
        </Group>
      </Affix>
    </form>
  );
}
