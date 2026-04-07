"use client";

import { useSearchParams } from "next/navigation";
import { RuleForm } from "../_components/rule-form";

export function EditRulePage() {
  const searchParams = useSearchParams();
  const ruleId = searchParams.get("ruleId") || "";

  return <RuleForm ruleId={ruleId} />;
}
