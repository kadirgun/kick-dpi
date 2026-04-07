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

// Global app settings types
export type DnsSettings = {
  provider: "Cloudflare" | "Quad9" | "NextDNS" | "Custom";
  custom_url?: string;
  timeout_ms: number;
  fallback_enabled: boolean;
  fallback_servers: string[];
};

export type SniSettings = {
  strategies: Record<string, boolean>;
};

export type StrategySettings = {
  wrong_checksum_decoy_ttl: number;
  fake_sni_decoy_ttl: number;
  overlap_decoy_ttl: number;
  ip_frag_first_payload_bytes: number;
};

export type PerformanceSettings = {
  process_cache_refresh_ms: number;
  flow_cache_sleep_ms: number;
  packet_buffer_size: number;
  connection_reset_buffer_kb: number;
  dns_buffer_size: number;
  sni_buffer_size: number;
};

export type AppSettings = {
  dns: DnsSettings;
  sni: SniSettings;
  strategy_params: StrategySettings;
  performance: PerformanceSettings;
};

export type Settings = {
  rules: Rule[];
  app: AppSettings;
};

export const useSettingsQuery = () => {
  return useQuery({
    queryKey: ["settings"],
    queryFn: async () => {
      const settings = await invoke<Settings>("get_settings");
      return settings || { rules: [], app: {} as AppSettings };
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
      const settings = await invoke<Settings>("get_settings");
      const updatedSettings: Settings = {
        ...settings,
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
      const settings = await invoke<Settings>("get_settings");
      const updatedSettings: Settings = {
        ...settings,
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
      const settings = await invoke<Settings>("get_settings");
      const updatedSettings: Settings = {
        ...settings,
        rules: settings?.rules.filter((rule) => rule.id !== ruleId) || [],
      };
      await invoke("set_settings", { settings: updatedSettings });
      await queryClient.invalidateQueries({ queryKey: ["settings"] });
    },
  });
};

export const useUpdateAppSettingsMutation = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (appSettings: AppSettings) => {
      const currentSettings = await invoke<Settings>("get_settings");
      await invoke("set_settings", {
        settings: {
          ...currentSettings,
          app: appSettings,
        },
      });
      await queryClient.invalidateQueries({ queryKey: ["settings"] });
    },
  });
};

export const useAppSettingsQuery = () => {
  const { data: settings, ...other } = useSettingsQuery();
  return {
    data: settings?.app,
    ...other,
  };
};

export const resetConnectionsForRules = (ruleIds: string[]): Promise<void> =>
  invoke("reset_connections_for_rule_ids", { ruleIds });
