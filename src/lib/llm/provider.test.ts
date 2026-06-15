import { describe, expect, it } from 'vitest'
import type { Finding, NormalizedEvent } from '../../types'
import {
  coerceEnrichment,
  fallbackRecommendations,
  fallbackSummary,
  parseJsonLoose,
  type EnrichmentRequest,
} from './provider'

function event(): NormalizedEvent {
  return { id: 'e1', source: 'raw', message: 'event', raw: {} }
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'f1',
    title: 'Encoded PowerShell',
    severity: 'high',
    description: 'Base64-encoded PowerShell command observed.',
    evidence: ['powershell.exe -enc ZQBjAGgAbwA='],
    techniques: [],
    recommendation: 'Isolate the host and review the decoded command.',
    ...overrides,
  }
}

function request(overrides: Partial<EnrichmentRequest> = {}): EnrichmentRequest {
  return {
    events: [],
    findings: [],
    riskScore: 0,
    severity: 'info',
    ...overrides,
  }
}

describe('parseJsonLoose', () => {
  it('parses a plain JSON object', () => {
    expect(parseJsonLoose('{"summary": "ok"}')).toEqual({ summary: 'ok' })
  })

  it('extracts JSON from a fenced ```json block', () => {
    const text = 'Here is the result:\n```json\n{"summary": "fenced"}\n```'
    expect(parseJsonLoose(text)).toEqual({ summary: 'fenced' })
  })

  it('extracts JSON from a bare fenced block', () => {
    const text = '```\n{"summary": "bare"}\n```'
    expect(parseJsonLoose(text)).toEqual({ summary: 'bare' })
  })

  it('recovers the outermost object when the model adds commentary', () => {
    const text = 'Sure! {"summary": "messy"} Hope that helps.'
    expect(parseJsonLoose(text)).toEqual({ summary: 'messy' })
  })

  it('returns undefined when there is no JSON to find', () => {
    expect(parseJsonLoose('no json here')).toBeUndefined()
  })
})

describe('coerceEnrichment', () => {
  it('passes through a well-formed object and trims the summary', () => {
    const result = coerceEnrichment(
      {
        summary: '  three findings  ',
        recommendations: ['isolate host', 42, 'reset creds'],
        notes: { f1: 'looks malicious', f2: 7 },
      },
      request({ findings: [finding()] }),
    )
    expect(result.summary).toBe('three findings')
    expect(result.recommendations).toEqual(['isolate host', 'reset creds'])
    expect(result.notes).toEqual({ f1: 'looks malicious' })
  })

  it('falls back when fields are missing or the wrong type', () => {
    const req = request({ findings: [finding()] })
    const result = coerceEnrichment({ summary: '   ', recommendations: 'nope' }, req)
    expect(result.summary).toBe(fallbackSummary(req))
    expect(result.recommendations).toEqual(fallbackRecommendations(req))
    expect(result.notes).toEqual({})
  })

  it('treats a non-object value as empty and uses fallbacks', () => {
    const req = request({ findings: [finding()] })
    const result = coerceEnrichment(null, req)
    expect(result.summary).toBe(fallbackSummary(req))
    expect(result.recommendations).toEqual(fallbackRecommendations(req))
  })
})

describe('fallbackSummary', () => {
  it('reports a clean result when there are no findings', () => {
    const summary = fallbackSummary(request({ events: [event(), event()] }))
    expect(summary).toBe(
      'No suspicious activity matched the current detection rules across 2 event(s).',
    )
  })

  it('summarizes count, severity, score, and titles when there are findings', () => {
    const summary = fallbackSummary(
      request({
        events: [event()],
        findings: [finding({ title: 'Encoded PowerShell' })],
        severity: 'high',
        riskScore: 45,
      }),
    )
    expect(summary).toContain('1 finding(s)')
    expect(summary).toContain('Highest severity: high')
    expect(summary).toContain('45/100')
    expect(summary).toContain('Encoded PowerShell')
  })
})

describe('fallbackRecommendations', () => {
  it('advises normal monitoring when there are no findings', () => {
    expect(fallbackRecommendations(request())).toEqual([
      'No action required. Continue normal monitoring.',
    ])
  })

  it('de-duplicates identical recommendations across findings, preserving order', () => {
    const recs = fallbackRecommendations(
      request({
        findings: [
          finding({ id: 'a', recommendation: 'Isolate the host.' }),
          finding({ id: 'b', recommendation: 'Reset credentials.' }),
          finding({ id: 'c', recommendation: 'Isolate the host.' }),
        ],
      }),
    )
    expect(recs).toEqual(['Isolate the host.', 'Reset credentials.'])
  })
})
