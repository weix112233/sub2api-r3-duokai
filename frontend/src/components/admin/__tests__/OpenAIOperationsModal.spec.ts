import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'

const mocks = vi.hoisted(() => ({
  getSettings: vi.fn(), setSettings: vi.fn(), pool: vi.fn(), reasoning: vi.fn(), events: vi.fn(),
  list: vi.fn(), showSuccess: vi.fn()
}))
vi.mock('@/api/admin/openaiOperations', () => ({ openaiOperationsAPI: mocks }))
vi.mock('@/api/admin/tlsFingerprintProfile', () => ({ tlsFingerprintProfileAPI: mocks }))
vi.mock('@/stores/app', () => ({ useAppStore: () => mocks }))
vi.mock('@/utils/format', () => ({ formatDateTime: (value: string) => value }))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))
vi.mock('@/components/common/BaseDialog.vue', () => ({
  default: { props: ['show'], template: '<section v-if="show"><slot /></section>' }
}))
import OpenAIOperationsModal from '../OpenAIOperationsModal.vue'
import type { OpenAIOperationsSettings } from '@/api/admin/openaiOperations'

const defaults = (): OpenAIOperationsSettings => ({
  recovery: { enabled: false, interval_minutes: 10, failure_threshold: 5, backoff_minutes: 360, cooldown_minutes: 10 },
  reasoning: { window_hours: 24, sample_limit: 1000, threshold: 50 },
  new_account_defaults: null
})
let wrapper: VueWrapper | undefined
beforeEach(() => {
  vi.clearAllMocks()
  mocks.getSettings.mockResolvedValue(defaults())
  mocks.setSettings.mockImplementation(async value => value)
  mocks.pool.mockResolvedValue({ total: 1, schedulable: 0, cooling: 1, error: 0, accounts: [{
    account_id: 1, name: 'local', status: 'active', schedulable: false, cooldowns: [{
      reason: '429', until: '2099-01-01T00:00:00Z', remaining_seconds: 10
    }], sticky_escape_reason: 'ttft', tls_proxy_fallback: true
  }], recovery: [], observed_at: '2026-09-13T00:00:00Z' })
  mocks.reasoning.mockResolvedValue([{ model: 'local-model', reasoning_tokens: 321, hits: 50, suspected_truncation: true }])
  mocks.events.mockResolvedValue([])
  mocks.list.mockResolvedValue([])
})
afterEach(() => { wrapper?.unmount(); vi.useRealTimers() })
async function open() {
  wrapper = mount(OpenAIOperationsModal, { props: { show: true } })
  await flushPromises()
  return wrapper
}
async function tab(view: string) {
  await wrapper!.findAll('[role=tab]').find(b => b.text() === `admin.openaiOperations.${view}`)!.trigger('click')
}
describe('OpenAI operations', () => {
  it('shows existing cooldown and sticky escape separately without writing settings', async () => {
    const w = await open()
    expect(w.text()).toContain('429')
    expect(w.text()).toContain('ttft')
    expect(w.text()).toContain('admin.openaiOperations.proxyFallback')
    expect(mocks.setSettings).not.toHaveBeenCalled()
    await tab('reasoning')
    expect(w.text()).toContain('321')
    expect(w.text()).toContain('50')
    expect(w.text()).toContain('admin.openaiOperations.suspected')
  })
  it('preserves null and explicit false template fields and saves only on submit', async () => {
    const w = await open()
    await tab('settings')
    expect(w.get('[data-testid=recovery-enabled]').element).toHaveProperty('checked', false)
    await w.get('[data-testid=template-enabled]').setValue(true)
    await w.get('[data-testid=template-tls]').setValue('false')
    expect(mocks.setSettings).not.toHaveBeenCalled()
    await w.get('form').trigger('submit')
    await flushPromises()
    expect(mocks.setSettings).toHaveBeenCalledWith(expect.objectContaining({
      recovery: expect.objectContaining({ enabled: false }),
      new_account_defaults: { proxy_id: null, enable_tls_fingerprint: false, tls_fingerprint_profile_id: null, codex_fingerprint_mode: null, concurrency: null }
    }))
  })
  it('does not overwrite unsaved settings during data refresh', async () => {
    const w = await open()
    await tab('settings')
    await w.get('[data-testid=recovery-enabled]').setValue(true)
    await w.get('button[aria-label="common.refresh"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-testid=recovery-enabled]').element).toHaveProperty('checked', true)
    expect(mocks.getSettings).toHaveBeenCalledTimes(1)
  })
  it('ignores stale loads after close and surfaces failures', async () => {
    let finish!: (value: OpenAIOperationsSettings) => void
    mocks.getSettings.mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
    wrapper = mount(OpenAIOperationsModal, { props: { show: true } })
    await wrapper.setProps({ show: false })
    finish(defaults())
    await flushPromises()
    mocks.getSettings.mockRejectedValueOnce(new Error('offline'))
    await wrapper.setProps({ show: true })
    await flushPromises()
    expect(wrapper.get('[role=alert]').text()).toContain('loadFailed')
    expect(wrapper.find('button[type=submit]').exists()).toBe(false)
  })
})
