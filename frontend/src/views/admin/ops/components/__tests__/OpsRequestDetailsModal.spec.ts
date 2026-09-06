import { describe, expect, it, vi } from 'vitest'
import { defineComponent, ref } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import OpsRequestDetailsModal from '../OpsRequestDetailsModal.vue'

const mockListRequestDetails = vi.fn()

vi.mock('@/api/admin/ops', () => ({
  opsAPI: {
    listRequestDetails: (...args: any[]) => mockListRequestDetails(...args),
  },
}))

vi.mock('@/stores', () => ({
  useAppStore: () => ({
    showError: vi.fn(),
    showWarning: vi.fn(),
  }),
}))

vi.mock('@/composables/useClipboard', () => ({
  useClipboard: () => ({
    copyToClipboard: vi.fn().mockResolvedValue(true),
  }),
}))

vi.mock('@vueuse/core', () => ({
  useMediaQuery: () => ref(true),
}))

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return {
    ...actual,
    useI18n: () => ({
      t: (key: string) => key,
    }),
  }
})

const BaseDialogStub = defineComponent({
  props: {
    show: { type: Boolean, default: false },
    title: { type: String, default: '' },
  },
  template: '<div v-if="show"><slot /></div>',
})

describe('OpsRequestDetailsModal TTFT drill-down', () => {
  it('requests TTFT ordering and renders per-request TTFT', async () => {
    mockListRequestDetails.mockResolvedValue({
      items: [
        {
          kind: 'success',
          created_at: '2026-09-02T09:00:00Z',
          request_id: 'req-anonymous',
          platform: 'openai',
          model: 'gpt-test',
          duration_ms: 1400,
          first_token_ms: 320,
          stream: true,
        },
        {
          kind: 'error',
          created_at: '2026-09-02T08:59:00Z',
          request_id: 'req-error',
          platform: 'openai',
          model: 'gpt-test',
          duration_ms: 500,
          first_token_ms: null,
          status_code: 502,
          stream: true,
        },
      ],
      total: 2,
      page: 1,
      page_size: 10,
    })

    const wrapper = mount(OpsRequestDetailsModal, {
      props: {
        modelValue: false,
        timeRange: '1h',
        preset: {
          title: 'TTFT',
          sort: 'ttft_desc',
        },
      },
      global: {
        stubs: {
          BaseDialog: BaseDialogStub,
          Pagination: true,
        },
      },
    })
    await wrapper.setProps({ modelValue: true })
    await flushPromises()

    expect(mockListRequestDetails).toHaveBeenCalledWith(
      expect.objectContaining({
        sort: 'ttft_desc',
        kind: 'all',
        page: 1,
        page_size: 10,
      })
    )

    const ttftCells = wrapper.findAll('[data-testid="request-detail-ttft"]')
    expect(ttftCells).toHaveLength(2)
    expect(ttftCells[0].text()).toBe('320 ms')
    expect(ttftCells[1].text()).toBe('-')
  })
})
