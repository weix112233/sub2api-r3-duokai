import { describe, expect, it } from 'vitest'
import { eagerPaymentSdks } from '../../../build/payment-chunk-guard'

describe('payment SDK bundle boundaries', () => {
  it('permits payment SDKs behind dynamic routes', () => {
    expect(eagerPaymentSdks({
      'index.js': { type: 'chunk', isEntry: true, imports: ['shared.js'], dynamicImports: ['payment.js'] },
      'shared.js': { type: 'chunk', modules: { '/node_modules/vue/index.js': {} } },
      'payment.js': { type: 'chunk', imports: ['sdk.js'] },
      'sdk.js': { type: 'chunk', modules: { '/node_modules/@airwallex/components-sdk/index.js': {} } }
    })).toEqual([])
  })

  it('rejects transitive eager payment imports and handles chunk cycles', () => {
    expect(eagerPaymentSdks({
      'index.js': { type: 'chunk', isEntry: true, imports: ['shared.js'] },
      'shared.js': { type: 'chunk', imports: ['sdk.js', 'index.js'] },
      'sdk.js': {
        type: 'chunk',
        modules: {
          '/node_modules/@airwallex/components-sdk/index.js': {},
          'C:\\node_modules\\@stripe\\stripe-js\\index.js': {}
        }
      }
    })).toEqual(['airwallex', 'stripe'])
  })
})
