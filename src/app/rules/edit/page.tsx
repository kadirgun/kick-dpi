import { EditRulePage } from "./client";

export const dynamicParams = true;

export async function generateStaticParams() {
  return [];
}

export default function Page() {
  return <EditRulePage />;
}
