import { RuleForm } from "@/routes/rules/components/rule-form";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/rules/edit/$ruleId")({
  component: RouteComponent,
});

function RouteComponent() {
  const { ruleId } = Route.useParams();
  return <RuleForm ruleId={ruleId} />;
}
