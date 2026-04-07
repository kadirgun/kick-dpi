import { createFileRoute } from "@tanstack/react-router";
import { RuleForm } from "./components/rule-form";

export const Route = createFileRoute("/rules/create")({
  component: CreateRulePage,
});

function CreateRulePage() {
  return <RuleForm />;
}
