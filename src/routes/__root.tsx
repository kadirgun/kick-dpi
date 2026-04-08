import { ActionIcon, AppShell, Button, createTheme, Group, MantineProvider, ScrollArea, Stack } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { IconHome, IconPower, IconSettings } from "@tabler/icons-react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createRootRoute, Link, Outlet } from "@tanstack/react-router";
import { exit } from "@tauri-apps/plugin-process";

const theme = createTheme({
  scale: 0.87,
});

const queryClient = new QueryClient();

function RootLayout() {
  return (
    <MantineProvider theme={theme} defaultColorScheme="auto">
      <QueryClientProvider client={queryClient}>
        <Notifications />
        <AppShell header={{ height: 60 }} padding="md" mode="static" h="100vh">
          <AppShell.Header>
            <Group h="100%" justify="space-between" align="center" px="md">
              <Group align="center">
                <ActionIcon variant="default" size={36} component={Link} to="/">
                  <IconHome size={16} />
                </ActionIcon>
                <Button variant="default" component={Link} to="/rules/create">
                  Create Rule
                </Button>
                <ActionIcon variant="default" size={36} component={Link} to="/settings" title="Application Settings">
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

          <AppShell.Main component={Stack} p={0}>
            <ScrollArea h="calc(100dvh - var(--app-shell-header-height))" offsetScrollbars>
              <Stack p="md">
                <Outlet />
              </Stack>
            </ScrollArea>
          </AppShell.Main>
        </AppShell>
      </QueryClientProvider>
    </MantineProvider>
  );
}

export const Route = createRootRoute({
  component: RootLayout,
});
