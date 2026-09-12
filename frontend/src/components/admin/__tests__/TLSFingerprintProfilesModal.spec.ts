import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'

const mocks = vi.hoisted(() => ({
  list: vi.fn(), create: vi.fn(), update: vi.fn(), delete: vi.fn(),
  parseYAML: vi.fn(), getDefaults: vi.fn(), setDefaults: vi.fn(),
  showError: vi.fn(), showSuccess: vi.fn()
}))
vi.mock('@/api/admin', () => ({ adminAPI: { tlsFingerprintProfiles: mocks } }))
vi.mock('@/stores/app', () => ({ useAppStore: () => mocks }))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))
vi.mock('@/components/common/BaseDialog.vue', () => ({
  default: { props: ['show'], template: '<section v-if="show"><slot /><slot name="footer" /></section>' }
}))
vi.mock('@/components/common/ConfirmDialog.vue', () => ({ default: { template: '<div />' } }))
import TLSFingerprintProfilesModal from '../TLSFingerprintProfilesModal.vue'

let wrapper: VueWrapper | undefined
const custom = {
  id: 11, name: 'local', description: null, enable_grease: false, shuffle_extensions: true,
  alpn_protocols: ['h2'], cipher_suites: [], curves: [], point_formats: [],
  signature_algorithms: [], supported_versions: [], key_share_groups: [], psk_modes: [], extensions: [],
  http2: { initial_window_size: 0, connection_window_update: 0, max_header_list_size: 0, enable_push: false }
}
beforeEach(() => {
  vi.clearAllMocks()
  mocks.list.mockResolvedValue([custom])
  mocks.getDefaults.mockResolvedValue({ openai_oauth_default_tls_profile_id: 0 })
  mocks.create.mockResolvedValue(custom)
  mocks.update.mockResolvedValue(custom)
  mocks.parseYAML.mockResolvedValue(custom)
  mocks.setDefaults.mockImplementation(async (value: unknown) => value)
})
afterEach(() => wrapper?.unmount())
async function open() {
  wrapper = mount(TLSFingerprintProfilesModal, { props: { show: true } })
  await flushPromises()
  return wrapper
}

describe('TLS profile management', () => {
  it('loads but never writes the operational default automatically', async () => {
    const w = await open()
    expect(mocks.getDefaults).toHaveBeenCalledTimes(1)
    expect(mocks.setDefaults).not.toHaveBeenCalled()
    await w.get('select').setValue('11')
    await w.findAll('button').find(b => b.text() === 'common.save')!.trigger('click')
    await flushPromises()
    expect(mocks.setDefaults).toHaveBeenCalledWith({ openai_oauth_default_tls_profile_id: 11 })
  })

  it('edits HTTP/2 zero/false and shuffle without losing values', async () => {
    const w = await open()
    await w.get('button[title="common.edit"]').trigger('click')
    expect(w.get('input[type=checkbox]').element).toHaveProperty('checked', true)
    await w.findAll('button').find(b => b.text() === 'common.update')!.trigger('click')
    await flushPromises()
    expect(mocks.update).toHaveBeenCalledWith(11, expect.objectContaining({
      shuffle_extensions: true, alpn_protocols: ['h2'], http2: custom.http2
    }))
  })

  it('creates no-ALPN profiles and parses YAML through the strict API', async () => {
    const w = await open()
    await w.findAll('button').find(b => b.text() === 'admin.tlsFingerprintProfiles.createProfile')!.trigger('click')
    const yaml = 'name: external'
    await w.get('textarea').setValue(yaml)
    await w.findAll('button').find(b => b.text() === 'admin.tlsFingerprintProfiles.form.parseYaml')!.trigger('click')
    await flushPromises()
    expect(mocks.parseYAML).toHaveBeenCalledWith(yaml)
    await w.get('#tls-alpn-mode').setValue('none')
    for (const input of w.findAll('input[inputmode=numeric]')) await input.setValue('')
    await w.findAll('select').at(-1)!.setValue('')
    await w.findAll('button').find(b => b.text() === 'common.create')!.trigger('click')
    await flushPromises()
    expect(mocks.create).toHaveBeenCalledWith(expect.objectContaining({
      alpn_protocols: [], http2: null, shuffle_extensions: true
    }))
  })

  it('does not restore a stale YAML response into a closed form', async () => {
    let finish!: (value: typeof custom) => void
    mocks.parseYAML.mockImplementation(() => new Promise(resolve => { finish = resolve }))
    const w = await open()
    await w.findAll('button').find(b => b.text() === 'admin.tlsFingerprintProfiles.createProfile')!.trigger('click')
    await w.get('textarea').setValue('name: external')
    await w.findAll('button').find(b => b.text() === 'admin.tlsFingerprintProfiles.form.parseYaml')!.trigger('click')
    await w.setProps({ show: false })
    finish(custom)
    await flushPromises()
    await w.setProps({ show: true })
    await flushPromises()
    await w.findAll('button').find(b => b.text() === 'admin.tlsFingerprintProfiles.createProfile')!.trigger('click')
    expect(w.get('input[required]').element).toHaveProperty('value', '')
    expect(w.get('#tls-alpn-mode').element).toHaveProperty('value', 'inherit')
  })
})
