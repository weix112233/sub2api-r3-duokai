import type { CreateProfileRequest, HTTP2ProfileConfig } from '@/api/admin/tlsFingerprintProfile'

export type ALPNMode = 'inherit' | 'none' | 'custom'
export const http2NumericFields = ['initial_window_size', 'connection_window_update', 'max_header_list_size'] as const
export type HTTP2NumericField = typeof http2NumericFields[number]

export interface TransportForm {
  shuffle_extensions: boolean
  alpnMode: ALPNMode
  initial_window_size: string
  connection_window_update: string
  max_header_list_size: string
  enable_push: '' | 'true' | 'false'
}

export function transportFormFromProfile(profile: CreateProfileRequest): TransportForm {
  return {
    shuffle_extensions: profile.shuffle_extensions ?? false,
    alpnMode: profile.alpn_protocols == null ? 'inherit' : profile.alpn_protocols.length ? 'custom' : 'none',
    initial_window_size: profile.http2?.initial_window_size?.toString() ?? '',
    connection_window_update: profile.http2?.connection_window_update?.toString() ?? '',
    max_header_list_size: profile.http2?.max_header_list_size?.toString() ?? '',
    enable_push: profile.http2?.enable_push == null ? '' : profile.http2.enable_push ? 'true' : 'false'
  }
}

export function parseNumericArray(input: string, max = 65535): number[] {
  if (!input.trim()) return []
  return input.split(',').map(raw => {
    const text = raw.trim()
    if (!/^(?:0x[\da-f]+|\d+)$/i.test(text)) throw new Error('Invalid numeric array')
    const value = Number(text)
    if (!Number.isSafeInteger(value) || value > max) throw new Error('Numeric array value out of range')
    return value
  })
}

export function transportFields(form: TransportForm, protocols: string): Pick<CreateProfileRequest, 'shuffle_extensions' | 'alpn_protocols' | 'http2'> {
  const alpn = form.alpnMode === 'inherit' ? null
    : form.alpnMode === 'none' ? [] : protocols.split(',').map(s => s.trim()).filter(Boolean)
  if (form.alpnMode === 'custom' && !alpn?.length) throw new Error('ALPN protocols required')
  if (alpn && (new Set(alpn).size !== alpn.length || alpn.some(p => !['h2', 'http/1.1'].includes(p)))) {
    throw new Error('Invalid ALPN protocols')
  }
  const http2: HTTP2ProfileConfig = {}
  const limits: Record<HTTP2NumericField, number> = {
    initial_window_size: 2147483647,
    connection_window_update: 2147418112,
    max_header_list_size: 4294967295
  }
  for (const key of http2NumericFields) {
    const input = form[key].trim()
    if (!input) continue
    if (!/^\d+$/.test(input)) throw new Error(`Invalid ${key}`)
    const value = Number(input)
    if (!Number.isSafeInteger(value) || value > limits[key]) throw new Error(`Invalid ${key}`)
    http2[key] = value
  }
  if (form.enable_push !== '') http2.enable_push = form.enable_push === 'true'
  const configured = Object.keys(http2).length > 0
  if (configured && !alpn?.includes('h2')) throw new Error('HTTP/2 requires h2 ALPN')
  return {
    shuffle_extensions: form.shuffle_extensions,
    alpn_protocols: alpn,
    http2: configured ? http2 : null
  }
}
