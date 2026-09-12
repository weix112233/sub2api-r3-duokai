/**
 * Admin TLS Fingerprint Profile API endpoints
 * Handles TLS fingerprint profile CRUD for administrators
 */

import { apiClient } from '../client'

export interface HTTP2ProfileConfig {
  initial_window_size?: number
  connection_window_update?: number
  max_header_list_size?: number
  enable_push?: boolean
}

export interface TLSProfileDefaults {
  openai_oauth_default_tls_profile_id: number
}

/**
 * TLS fingerprint profile interface
 */
export interface TLSFingerprintProfile {
  id: number
  name: string
  description: string | null
  enable_grease: boolean
  shuffle_extensions: boolean
  http2: HTTP2ProfileConfig | null
  cipher_suites: number[]
  curves: number[]
  point_formats: number[]
  signature_algorithms: number[]
  alpn_protocols: string[] | null
  supported_versions: number[]
  key_share_groups: number[]
  psk_modes: number[]
  extensions: number[]
  created_at: string
  updated_at: string
}

/**
 * Create profile request
 */
export interface CreateProfileRequest {
  name: string
  description?: string | null
  enable_grease?: boolean
  shuffle_extensions?: boolean
  http2?: HTTP2ProfileConfig | null
  cipher_suites?: number[]
  curves?: number[]
  point_formats?: number[]
  signature_algorithms?: number[]
  alpn_protocols?: string[] | null
  supported_versions?: number[]
  key_share_groups?: number[]
  psk_modes?: number[]
  extensions?: number[]
}

/**
 * Update profile request
 */
export interface UpdateProfileRequest {
  name?: string
  description?: string | null
  enable_grease?: boolean
  shuffle_extensions?: boolean
  http2?: HTTP2ProfileConfig | null
  cipher_suites?: number[]
  curves?: number[]
  point_formats?: number[]
  signature_algorithms?: number[]
  alpn_protocols?: string[] | null
  supported_versions?: number[]
  key_share_groups?: number[]
  psk_modes?: number[]
  extensions?: number[]
}

export async function list(): Promise<TLSFingerprintProfile[]> {
  const { data } = await apiClient.get<TLSFingerprintProfile[]>('/admin/tls-fingerprint-profiles')
  return data
}

export async function getById(id: number): Promise<TLSFingerprintProfile> {
  const { data } = await apiClient.get<TLSFingerprintProfile>(`/admin/tls-fingerprint-profiles/${id}`)
  return data
}

export async function create(profileData: CreateProfileRequest): Promise<TLSFingerprintProfile> {
  const { data } = await apiClient.post<TLSFingerprintProfile>('/admin/tls-fingerprint-profiles', profileData)
  return data
}

export async function update(id: number, updates: UpdateProfileRequest): Promise<TLSFingerprintProfile> {
  const { data } = await apiClient.put<TLSFingerprintProfile>(`/admin/tls-fingerprint-profiles/${id}`, updates)
  return data
}

export async function deleteProfile(id: number): Promise<{ message: string }> {
  const { data } = await apiClient.delete<{ message: string }>(`/admin/tls-fingerprint-profiles/${id}`)
  return data
}

export async function parseYAML(yaml: string): Promise<CreateProfileRequest> {
  const { data } = await apiClient.post<CreateProfileRequest>('/admin/tls-fingerprint-profiles/parse-yaml', { yaml })
  return data
}

export async function getDefaults(): Promise<TLSProfileDefaults> {
  const { data } = await apiClient.get<TLSProfileDefaults>('/admin/tls-fingerprint-profiles/defaults')
  return data
}

export async function setDefaults(defaults: TLSProfileDefaults): Promise<TLSProfileDefaults> {
  const { data } = await apiClient.put<TLSProfileDefaults>('/admin/tls-fingerprint-profiles/defaults', defaults)
  return data
}

export const tlsFingerprintProfileAPI = {
  list,
  getById,
  create,
  update,
  delete: deleteProfile,
  parseYAML,
  getDefaults,
  setDefaults
}

export default tlsFingerprintProfileAPI
