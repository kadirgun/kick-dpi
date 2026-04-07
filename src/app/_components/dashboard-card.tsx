import { Card, Group, Paper, Stack, Text } from "@mantine/core";
import type React from "react";

export type DashBoardCardProps = {
  title: string;
  children?: React.ReactNode;
  icon?: React.ReactNode;
  rightSection?: React.ReactNode;
  footer?: React.ReactNode;
};

export function DashBoardCard({ title, icon, children, rightSection, footer }: DashBoardCardProps) {
  return (
    <Card radius="md" withBorder>
      <Card.Section inheritPadding py={8} bg="dark.8">
        <Group justify="space-between" wrap="nowrap">
          <Group wrap="nowrap" gap="xs">
            {icon && icon}
            <Text size="sm" fw={500}>
              {title}
            </Text>
          </Group>

          {rightSection && rightSection}
        </Group>
      </Card.Section>

      <Card.Section bg="dark.8" flex={1} component={Stack}>
        <Paper withBorder radius="md" component={Stack} flex={1}>
          {children}
        </Paper>
      </Card.Section>

      {footer && (
        <Card.Section withBorder inheritPadding py="xs">
          {footer}
        </Card.Section>
      )}
    </Card>
  );
}
