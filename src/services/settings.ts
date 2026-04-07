import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { invoke } from "@tauri-apps/api/core";
import { useMemo } from "react";

export type Rule = {
  id: string;
  name: string;
  hosts: string[];
  paths: string[];
  dns_enabled: boolean;
  sni_enabled: boolean;
};

export type AppSettings = {
  rules: Rule[];
};

export const useSettingsQuery = () => {
  return useQuery({
    queryKey: ["settings"],
    queryFn: async () => {
      const settings = await invoke<AppSettings>("get_settings");
      return settings || { rules: [] };
    },
  });
};

export const useRuleQuery = (ruleId: string) => {
  const { data: settings, ...other } = useSettingsQuery();

  const rule = useMemo(() => {
    return settings?.rules.find((r) => r.id === ruleId);
  }, [settings, ruleId]);

  return { data: rule, ...other };
};

export const useCreateRuleMutation = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (newRule: Rule) => {
      const settings = await invoke<AppSettings>("get_settings");
      const updatedSettings: AppSettings = {
        rules: [...(settings?.rules || []), newRule],
      };

      await invoke("set_settings", { settings: updatedSettings });
      await queryClient.invalidateQueries({ queryKey: ["settings"] });
    },
  });
};

export const useUpdateRuleMutation = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (updatedRule: Rule) => {
      const settings = await invoke<AppSettings>("get_settings");
      const updatedSettings: AppSettings = {
        rules: settings?.rules.map((rule) => (rule.id === updatedRule.id ? updatedRule : rule)) || [],
      };
      await invoke("set_settings", { settings: updatedSettings });
      await queryClient.invalidateQueries({ queryKey: ["settings"] });
    },
  });
};

export const useDeleteRuleMutation = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (ruleId: string) => {
      const settings = await invoke<AppSettings>("get_settings");
      const updatedSettings: AppSettings = {
        rules: settings?.rules.filter((rule) => rule.id !== ruleId) || [],
      };
      await invoke("set_settings", { settings: updatedSettings });
      await queryClient.invalidateQueries({ queryKey: ["settings"] });
    },
  });
};

export const resetConnectionsForRules = (ruleIds: string[]): Promise<void> =>
  invoke("reset_connections_for_rule_ids", { ruleIds });
