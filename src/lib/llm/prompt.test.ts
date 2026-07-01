import { describe, expect, it } from 'vitest'
import type { Finding, NormalizedEvent } from '../../types'
import type { EnrichmentRequest } from './provider'
import { SYSTEM_PROMPT, buildUserPrompt } from './prompt'

function event(i: number): NormalizedEvent {
  return {
    id: `evt-${i}`,
    source: 'sysmon',
    message: `event ${i}`,
    process: 'powershell.exe',
    raw: {},
  }
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'f1',
    title: 'Encoded PowerShell',
    severity: 'high',
    description: 'A base64 encoded command was executed.',
    evidence: ['line 1'],
    techniques: [
      { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution', url: 'https://attack.mitre.org/techniques/T1059/001/' },
    ],
    recommendation: 'Isolate the host.',
    ...overrides,
  }
}

function request(overrides: Partial<EnrichmentRequest> = {}): EnrichmentRequest {
  return {
    events: [event(0)],
    findings: [finding()],
    riskScore: 72,
    severity: 'high',
    ...overrides,
  }
}

/** Pull the JSON payload back out of the built user prompt. */
function payloadOf(prompt: string): any {
  return JSON.parse(prompt.slice(prompt.indexOf('{')))
}

describe('SYSTEM_PROMPT', () => {
  it('states the JSON-only output contract', () => {
    expect(SYSTEM_PROMPT).toContain('JSON only')
    expect(SYSTEM_PROMPT.length).toBeGreaterThan(0)
  })
})

describe('buildUserPrompt', () => {
  it('produces a parseable JSON payload', () => {
    expect(() => payloadOf(buildUserPrompt(request()))).not.toThrow()
  })

  it('carries the risk score and severity through', () => {
    const payload = payloadOf(buildUserPrompt(request({ riskScore: 40, severity: 'medium' })))
    expect(payload.riskScore).toBe(40)
    expect(payload.severity).toBe('medium')
  })

  it('caps the event sample at 25 even when more are supplied', () => {
    const events = Array.from({ length: 30 }, (_, i) => event(i))
    const payload = payloadOf(buildUserPrompt(request({ events })))
    expect(payload.eventSample).toHaveLength(25)
  })

  it('caps each finding evidence list at 8 lines', () => {
    const evidence = Array.from({ length: 12 }, (_, i) => `line ${i}`)
    const payload = payloadOf(buildUserPrompt(request({ findings: [finding({ evidence })] })))
    expect(payload.findings[0].evidence).toHaveLength(8)
  })

  it('flattens techniques into "id name" strings', () => {
    const payload = payloadOf(buildUserPrompt(request()))
    expect(payload.findings[0].techniques).toEqual(['T1059.001 PowerShell'])
  })
})
