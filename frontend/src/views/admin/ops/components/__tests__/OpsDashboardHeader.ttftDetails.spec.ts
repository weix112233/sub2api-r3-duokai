import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

describe('OpsDashboardHeader TTFT drill-down', () => {
  it('keeps duration and TTFT detail ordering distinct', () => {
    const componentPath = resolve(
      process.cwd(),
      'src/views/admin/ops/components/OpsDashboardHeader.vue'
    )
    const source = readFileSync(componentPath, 'utf8')

    expect(source).toContain("openDetails({ title: t('admin.ops.latencyDuration'), sort: 'duration_desc' })")
    expect(source).toContain("openDetails({ title: t('admin.ops.ttftLabel'), sort: 'ttft_desc' })")
  })
})
