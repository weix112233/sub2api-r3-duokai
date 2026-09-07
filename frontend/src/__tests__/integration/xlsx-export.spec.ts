import { describe, expect, it } from 'vitest'
import * as XLSX from 'xlsx'

describe('usage workbook export dependency', () => {
  it('preserves appended rows, unicode and fixed-point cost strings', () => {
    const header = ['Model', 'Cost', 'Note']
    const rows = [
      ['gpt-6-astra', '0.123456', '\u6d4b\u8bd5'],
      ['gpt-6-astra', '0.000001', 'second page']
    ]
    const sheet = XLSX.utils.aoa_to_sheet([header])
    XLSX.utils.sheet_add_aoa(sheet, rows.slice(0, 1), { origin: -1 })
    XLSX.utils.sheet_add_aoa(sheet, rows.slice(1), { origin: -1 })
    const book = XLSX.utils.book_new()
    XLSX.utils.book_append_sheet(book, sheet, 'Usage')
    const data = XLSX.write(book, { bookType: 'xlsx', type: 'array' })
    const restored = XLSX.read(data, { type: 'array' })
    expect(XLSX.utils.sheet_to_json(restored.Sheets.Usage, { header: 1 })).toEqual([header, ...rows])
  })

  it('keeps formula-like log values as text rather than executable cells', () => {
    const value = '=1+1'
    const sheet = XLSX.utils.aoa_to_sheet([['Value'], [value], ['__proto__']])
    const book = XLSX.utils.book_new()
    XLSX.utils.book_append_sheet(book, sheet, 'Usage')
    const restored = XLSX.read(XLSX.write(book, { bookType: 'xlsx', type: 'array' }), { type: 'array' })
    expect(restored.Sheets.Usage.A2.v).toBe(value)
    expect(restored.Sheets.Usage.A2.t).toBe('s')
    expect(restored.Sheets.Usage.A2.f).toBeUndefined()
    expect(restored.Sheets.Usage.A3.v).toBe('__proto__')
  })
})
