import { describe, expect, it } from 'vitest'
import { parseNumericArray, transportFields, transportFormFromProfile } from '../tlsProfileForm'

describe('TLS profile transport form', () => {
  it('preserves omitted, empty and custom ALPN', () => {
    for (const alpn_protocols of [undefined, null, [], ['h2', 'http/1.1']]) {
      const form = transportFormFromProfile({ name: 'custom', alpn_protocols })
      expect(transportFields(form, alpn_protocols?.join(',') ?? '').alpn_protocols).toEqual(alpn_protocols ?? null)
    }
  })

  it('retains explicit zero and false when editing or importing YAML results', () => {
    const profile = {
      name: 'custom',
      shuffle_extensions: true,
      alpn_protocols: ['h2'],
      http2: { initial_window_size: 0, connection_window_update: 0, max_header_list_size: 0, enable_push: false }
    }
    expect(transportFields(transportFormFromProfile(profile), 'h2')).toEqual({
      shuffle_extensions: true, alpn_protocols: ['h2'], http2: profile.http2
    })
  })

  it('clears optional HTTP/2 values without fabricating defaults', () => {
    const form = transportFormFromProfile({ name: 'empty' })
    expect(transportFields(form, '')).toEqual({ shuffle_extensions: false, alpn_protocols: null, http2: null })
    form.enable_push = 'true'
    expect(() => transportFields(form, '')).toThrow()
    form.alpnMode = 'custom'
    expect(transportFields(form, 'h2').http2).toEqual({ enable_push: true })
  })

  it('rejects invalid values and connection-window overflow', () => {
    const form = transportFormFromProfile({ name: 'custom', alpn_protocols: ['h2'] })
    for (const value of ['-1', '1.5', 'NaN', '2147418113']) {
      form.connection_window_update = value
      expect(() => transportFields(form, 'h2')).toThrow()
    }
    form.connection_window_update = '2147418112'
    expect(transportFields(form, 'h2').http2?.connection_window_update).toBe(2147418112)
    expect(() => transportFields(form, 'h2,h2')).toThrow()
    expect(() => transportFields(form, 'unknown')).toThrow()
    expect(() => transportFields(form, '')).toThrow()
  })

  it('rejects partially parsed and out-of-range TLS values', () => {
    expect(parseNumericArray('0x1d, 23')).toEqual([29, 23])
    for (const input of ['123bad', '-1', '1.2', '65536', '1,']) expect(() => parseNumericArray(input)).toThrow()
    expect(() => parseNumericArray('256', 255)).toThrow()
  })
})
