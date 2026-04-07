"use client";

import { DnsSettings, useAppSettingsQuery, useUpdateAppSettingsMutation } from "@/services/settings";
import { Badge, Checkbox, Group, NumberInput, Select, Stack, Text, TextInput } from "@mantine/core";

const DNS_PROVIDERS = [
  { value: "Cloudflare", label: "Cloudflare (1.1.1.1)" },
  { value: "Quad9", label: "Quad9 (9.9.9.9)" },
  { value: "NextDNS", label: "NextDNS (45.90.28.1)" },
  { value: "Custom", label: "Custom URL" },
];

export function DnsSettingsForm() {
  const { data: settings } = useAppSettingsQuery();
  const updateMutation = useUpdateAppSettingsMutation();

  if (!settings) return null;

  const handleProviderChange = (value: string | null) => {
    if (value && settings) {
      updateMutation.mutate({
        ...settings,
        dns: {
          ...settings.dns,
          provider: value as DnsSettings["provider"],
        },
      });
    }
  };

  const handleCustomUrlChange = (value: string) => {
    if (settings) {
      updateMutation.mutate({
        ...settings,
        dns: {
          ...settings.dns,
          custom_url: value,
        },
      });
    }
  };

  const handleTimeoutChange = (value: number | string) => {
    if (settings) {
      const timeout = typeof value === "string" ? parseInt(value) || 2000 : value;
      updateMutation.mutate({
        ...settings,
        dns: {
          ...settings.dns,
          timeout_ms: Math.max(500, Math.min(timeout, 10000)),
        },
      });
    }
  };

  const handleFallbackToggle = (checked: boolean) => {
    if (settings) {
      updateMutation.mutate({
        ...settings,
        dns: {
          ...settings.dns,
          fallback_enabled: checked,
        },
      });
    }
  };

  const handleFallbackServersChange = (value: string) => {
    if (settings) {
      const servers = value
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      updateMutation.mutate({
        ...settings,
        dns: {
          ...settings.dns,
          fallback_servers: servers,
        },
      });
    }
  };

  return (
    <Stack gap="md">
      <div>
        <Select
          label="DNS Provider"
          placeholder="Select a provider"
          data={DNS_PROVIDERS}
          value={settings.dns.provider}
          onChange={handleProviderChange}
        />
        <Text size="xs" c="dimmed" mt={4}>
          Choose a DoH (DNS over HTTPS) provider
        </Text>
      </div>

      {settings.dns.provider === "Custom" && (
        <div>
          <TextInput
            label="Custom DoH URL"
            placeholder="https://dns.example.com/dns-query"
            value={settings.dns.custom_url || ""}
            onChange={(e) => handleCustomUrlChange(e.currentTarget.value)}
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
          value={settings.dns.timeout_ms}
          onChange={handleTimeoutChange}
          min={500}
          max={10000}
          step={100}
        />
        <Text size="xs" c="dimmed" mt={4}>
          DoH request timeout duration (500-10000 ms)
        </Text>
      </div>

      <Checkbox
        label="Enable Fallback DNS"
        description="Use traditional DNS servers if DoH fails"
        checked={settings.dns.fallback_enabled}
        onChange={(e) => handleFallbackToggle(e.currentTarget.checked)}
      />

      {settings.dns.fallback_enabled && (
        <div>
          <TextInput
            label="Fallback DNS Servers"
            placeholder="8.8.8.8, 8.8.4.4"
            value={settings.dns.fallback_servers.join(", ")}
            onChange={(e) => handleFallbackServersChange(e.currentTarget.value)}
          />
          <Text size="xs" c="dimmed" mt={4}>
            Comma-separated IP addresses (e.g. 8.8.8.8, 8.8.4.4)
          </Text>
        </div>
      )}

      <Group>
        <Badge>Active: {settings.dns.provider === "Custom" ? settings.dns.custom_url : settings.dns.provider}</Badge>
        <Badge>Timeout: {settings.dns.timeout_ms}ms</Badge>
      </Group>
    </Stack>
  );
}
