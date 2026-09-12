import { apiClient } from '../client'

export interface OpenAIOperationsSettings {
  recovery: { enabled: boolean; interval_minutes: number; failure_threshold: number; backoff_minutes: number; cooldown_minutes: number }
  reasoning: { window_hours: number; sample_limit: number; threshold: number }
  new_account_defaults: {
    proxy_id: number | null
    enable_tls_fingerprint: boolean | null
    tls_fingerprint_profile_id: number | null
    codex_fingerprint_mode: string | null
    concurrency: number | null
  } | null
}
export interface ReasoningBucket {
  model: string
  reasoning_tokens: number
  hits: number
  suspected_truncation: boolean
}
export interface RecoveryRecord {
  account_id: number
  attempts: number
  consecutive_failures: number
  last_attempt_at: string
  next_attempt_at: string
  classification: string
  outcome: string
  permanent: boolean
}
export interface RecoveryEvent {
  id: number
  account_id: number
  attempt: number
  classification: string
  action: string
  outcome: string
  created_at: string
}
export interface OperationalAccount {
  account_id: number
  name: string
  status: string
  schedulable: boolean
  cooldowns: { reason: string; until: string; remaining_seconds: number }[]
  sticky_escape_reason?: string
  tls_proxy_fallback: boolean
}
export interface AccountPoolState {
  observed_at: string
  total: number
  schedulable: number
  cooling: number
  error: number
  accounts: OperationalAccount[]
  recovery: RecoveryRecord[]
}
const base = '/admin/openai-operations'
export const openaiOperationsAPI = {
  async getSettings() { return (await apiClient.get<OpenAIOperationsSettings>(`${base}/settings`)).data },
  async setSettings(value: OpenAIOperationsSettings) { return (await apiClient.put<OpenAIOperationsSettings>(`${base}/settings`, value)).data },
  async reasoning(accountID = 0) { return (await apiClient.get<ReasoningBucket[]>(`${base}/reasoning`, { params: { account_id: accountID } })).data },
  async pool(groupID = 0) { return (await apiClient.get<AccountPoolState>(`${base}/pool`, { params: { group_id: groupID } })).data },
  async events(accountID = 0) { return (await apiClient.get<RecoveryEvent[]>(`${base}/recovery-events`, { params: { account_id: accountID } })).data }
}
