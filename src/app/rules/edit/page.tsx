import { Center, Loader } from "@mantine/core";
import { Suspense } from "react";
import { EditRulePage } from "./client";

export const dynamicParams = true;

export async function generateStaticParams() {
  return [];
}

export default function Page() {
  return (
    <Suspense
      fallback={
        <Center>
          <Loader />
        </Center>
      }
    >
      <EditRulePage />
    </Suspense>
  );
}
