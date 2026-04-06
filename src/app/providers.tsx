"use client";

import { createTheme, MantineProvider } from "@mantine/core";

const theme = createTheme({});

export function AppProviders({ children }: { children: React.ReactNode }) {
  return (
    <MantineProvider theme={theme} defaultColorScheme="auto">
      {children}
    </MantineProvider>
  );
}
