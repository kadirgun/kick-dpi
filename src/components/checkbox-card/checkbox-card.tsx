import { Checkbox, Group, Text } from "@mantine/core";
import type React from "react";
import classes from "./checkbox-card.module.css";

export type CheckboxCardProps = {
  label?: string | React.ReactNode;
  description?: string | React.ReactNode;
} & Checkbox.Card.Props;

export function CheckboxCard({ label, description, ...props }: CheckboxCardProps) {
  return (
    <Checkbox.Card className={classes.root} {...props}>
      <Group wrap="nowrap" align="flex-start">
        <Checkbox.Indicator />

        <div>
          <Text className={classes.label}>{label}</Text>
          <Text className={classes.description}>{description}</Text>
        </div>
      </Group>
    </Checkbox.Card>
  );
}
