"use client";

import { AppShell, createTheme, MantineProvider } from "@mantine/core";

const theme = createTheme({
  scale: 0.87,
});

export function AppProviders({ children }: { children: React.ReactNode }) {
  return (
    <MantineProvider theme={theme} defaultColorScheme="auto">
      <AppShell navbar={{ width: 300, breakpoint: "sm" }} padding="md">
        <AppShell.Navbar p="md">
          Navbar is collapsed on mobile at sm breakpoint. At that point it is no longer offset by padding in the main
          element and it takes the full width of the screen when opened.
        </AppShell.Navbar>
        <AppShell.Main>{children}</AppShell.Main>
      </AppShell>
    </MantineProvider>
  );
}
