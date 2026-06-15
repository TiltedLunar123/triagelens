import { describe, expect, it } from 'vitest'
import { SAMPLES } from '../data/samples'
import { analyze } from './analyze'
import { demoProvider } from './llm/demo'

function sampleText(id: string): string {
  const sample = SAMPLES.find((s) => s.id === id)
  if (!sample) throw new Error(`sample ${id} not found`)
  return sample.text
}

describe('analyze pipeline', () => {
  it('runs parse -> detect -> score -> enrich and attaches analyst notes', async () => {
    const result = await analyze(
      sampleText('windows-encoded-powershell'),
      demoProvider,
    )

    expect(result.events.length).toBeGreaterThan(0)
    expect(result.findings.length).toBeGreaterThan(0)
    expect(result.riskScore).toBeGreaterThan(0)
    expect(result.riskScore).toBeLessThanOrEqual(100)
    expect(result.generatedBy).toBe('demo')
    expect(result.meta.eventCount).toBe(result.events.length)
    expect(Number.isNaN(Date.parse(result.meta.analyzedAt))).toBe(false)

    for (const finding of result.findings) {
      expect(typeof finding.analystNote).toBe('string')
      expect((finding.analystNote ?? '').length).toBeGreaterThan(0)
    }
  })

  it('produces a clean report with no findings for benign input', async () => {
    const result = await analyze(sampleText('benign-backup'), demoProvider)

    expect(result.findings).toHaveLength(0)
    expect(result.riskScore).toBe(0)
    expect(result.severity).toBe('info')
    expect(result.summary).toContain('No suspicious activity')
    expect(result.recommendations).toEqual([
      'No action required. Continue normal monitoring.',
    ])
  })
})
