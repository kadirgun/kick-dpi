import { useQuery } from "@tanstack/react-query";
import { invoke } from "@tauri-apps/api/core";

export type Process = {
  pid: number;
  path: string;
};

export const useProcessesQuery = () => {
  return useQuery({
    queryKey: ["processes"],
    queryFn: async () => {
      const response = await invoke<Process[]>("get_processes");
      return response;
    },
  });
};
