import { describe, expect, it } from 'vitest'
import { demoProvider } from './demo'
import { fallbackRecommendations, fallbackSummary } from './provider'
import type { EnrichmentRequest } from './provider'
import type { Finding, MitreTechnique } from '../../types'

function technique(id: string, tactic: string): MitreTechnique {
  return { id, name: id, tactic, url: `https://attack.mitre.org/techniques/${id}/` }
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'f1',
    title: 'Encoded PowerShell',
    severity: 'high',
    description: 'PowerShell ran with an encoded command.',
    evidence: ['powershell -enc ...'],
    techniques: [technique('T1059.001', 'Execution')],
    recommendation: 'Review the host.',
    ...overrides,
  }
}

function request(findings: Finding[]): EnrichmentRequest {
  return {
    events: [],
    findings,
    riskScore: findings.length ? 80 : 0,
    severity: findings.length ? 'high' : 'info',
  }
}

describe('demoProvider', () => {
  it('identifies itself as the rule-based demo backend', () => {
    expect(demoProvider.id).toBe('demo')
    expect(demoProvider.label).toMatch(/demo/i)
  })

  it('builds a per-finding note with deduplicated tactics', async () => {
    const f = finding({
      id: 'abc',
      techniques: [
        technique('T1059.001', 'Execution'),
        technique('T1059.003', 'Execution'),
        technique('T1140', 'Defense Evasion'),
      ],
    })
    const result = await demoProvider.enrich(request([f]))
    expect(result.notes.abc).toBe(
      'PowerShell ran with an encoded command. Mapped tactics: Execution, Defense Evasion.',
    )
  })

  it('notes n/a when a finding has no techniques', async () => {
    const f = finding({ id: 'noTech', techniques: [] })
    const result = await demoProvider.enrich(request([f]))
    expect(result.notes.noTech).toBe(
      'PowerShell ran with an encoded command. Mapped tactics: n/a.',
    )
  })

  it('delegates summary and recommendations to the shared fallbacks', async () => {
    const req = request([
      finding(),
      finding({ id: 'f2', recommendation: 'Isolate the host.' }),
    ])
    const result = await demoProvider.enrich(req)
    expect(result.summary).toBe(fallbackSummary(req))
    expect(result.recommendations).toEqual(fallbackRecommendations(req))
  })

  it('reports a clean summary and no notes when there are no findings', async () => {
    const result = await demoProvider.enrich(request([]))
    expect(result.summary).toContain('No suspicious activity')
    expect(result.recommendations).toEqual([
      'No action required. Continue normal monitoring.',
    ])
    expect(result.notes).toEqual({})
  })
})
