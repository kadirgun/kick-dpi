import { Box, SimpleGrid, Stack, Text } from "@mantine/core";
import { IconNetwork, IconRoute, IconShieldShare } from "@tabler/icons-react";
import { createFileRoute } from "@tanstack/react-router";
import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import { DashBoardCard } from "../app/_components/dashboard-card";
import { RulesTable } from "../app/_components/rules-table";

export const Route = createFileRoute("/")({
  component: Home,
});

function Home() {
  const [dnsPackets, setDnsPackets] = useState(0);
  const [sniPackets, setSniPackets] = useState(0);

  useEffect(() => {
    let timerId: ReturnType<typeof setTimeout>;

    const fetchData = async () => {
      await invoke<number>("get_dns_packets")
        .then((count) => {
          setDnsPackets(count);
        })
        .finally(() => {
          timerId = setTimeout(fetchData, 1000);
        });
    };

    fetchData();

    return () => {
      clearTimeout(timerId);
    };
  }, []);

  useEffect(() => {
    let timerId: ReturnType<typeof setTimeout>;

    const fetchData = async () => {
      await invoke<number>("get_sni_packets")
        .then((count) => {
          setSniPackets(count);
        })
        .finally(() => {
          timerId = setTimeout(fetchData, 1000);
        });
    };

    fetchData();

    return () => {
      clearTimeout(timerId);
    };
  }, []);

  return (
    <Stack>
      <SimpleGrid cols={2} mt="md">
        <DashBoardCard title="SNI Packets" icon={<IconShieldShare size={12} />}>
          <Stack gap="xs" p="md">
            <Text c="dimmed" size="sm">
              Total number of SNI packets captured since the application started.
            </Text>
            <Text fz={30} fw={700} ta="center">
              {sniPackets}
            </Text>
          </Stack>
        </DashBoardCard>
        <DashBoardCard title="DNS Packets" icon={<IconNetwork size={12} />}>
          <Stack gap="xs" p="md">
            <Text c="dimmed" size="sm">
              Total number of DNS packets captured since the application started.
            </Text>
            <Text fz={30} fw={700} ta="center">
              {dnsPackets}
            </Text>
          </Stack>
        </DashBoardCard>
      </SimpleGrid>
      <DashBoardCard title="Active Rules" icon={<IconRoute size={12} />}>
        <Box p="md">
          <RulesTable />
        </Box>
      </DashBoardCard>
    </Stack>
  );
}
