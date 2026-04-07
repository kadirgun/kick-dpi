"use client";

import { ActionIcon, AppShell, Button, createTheme, Group, MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { IconHome, IconPower, IconSettings } from "@tabler/icons-react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { exit } from "@tauri-apps/plugin-process";
import Link from "next/link";

const theme = createTheme({
  scale: 0.87,
});

const queryClient = new QueryClient();

export function AppProviders({ children }: { children: React.ReactNode }) {
  return (
    <MantineProvider theme={theme} defaultColorScheme="auto">
      <QueryClientProvider client={queryClient}>
        <Notifications />
        <AppShell header={{ height: 60 }} padding="md">
          <AppShell.Header>
            <Group h="100%" justify="space-between" align="center" px="md">
              <Group align="center">
                <ActionIcon variant="default" size={36} component={Link} href={`/`}>
                  <IconHome size={16} />
                </ActionIcon>
                <Button variant="default" component={Link} href={`/rules/create`}>
                  Create Rule
                </Button>
                <ActionIcon
                  variant="default"
                  size={36}
                  component={Link}
                  href={`/settings`}
                  title="Application Settings"
                >
                  <IconSettings size={16} />
                </ActionIcon>
              </Group>

              <Group align="center">
                <ActionIcon variant="light" color="red" size={36} onClick={() => exit(0)}>
                  <IconPower size={16} />
                </ActionIcon>
              </Group>
            </Group>
          </AppShell.Header>

          <AppShell.Main>{children}</AppShell.Main>
        </AppShell>
      </QueryClientProvider>
    </MantineProvider>
  );
}
