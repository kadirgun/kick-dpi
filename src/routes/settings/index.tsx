import { useAppSettingsQuery } from "@/services/settings";
import { Alert, LoadingOverlay, Stack, Tabs, Text } from "@mantine/core";
import { createFileRoute } from "@tanstack/react-router";
import { DnsSettingsForm } from "./-components/dns-settings-form";
import { PerformanceForm } from "./-components/performance-form";
import { SniStrategiesForm } from "./-components/sni-strategies-form";

export const Route = createFileRoute("/settings/")({
  component: SettingsPage,
});

function SettingsPage() {
  const { isLoading, error } = useAppSettingsQuery();

  if (error) {
    return (
      <Alert color="red" title="Error">
        Failed to load settings: {String(error)}
      </Alert>
    );
  }

  return (
    <Stack gap="lg">
      <div>
        <Text fw={700} size="lg">
          Application Settings
        </Text>
      </div>

      <LoadingOverlay visible={isLoading} />

      <Tabs defaultValue="dns">
        <Tabs.List>
          <Tabs.Tab value="dns">DNS</Tabs.Tab>
          <Tabs.Tab value="sni">SNI Strategies</Tabs.Tab>
          <Tabs.Tab value="performance">Performance</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="dns" pt="md">
          <DnsSettingsForm />
        </Tabs.Panel>

        <Tabs.Panel value="sni" pt="md">
          <SniStrategiesForm />
        </Tabs.Panel>

        <Tabs.Panel value="performance" pt="md">
          <PerformanceForm />
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
