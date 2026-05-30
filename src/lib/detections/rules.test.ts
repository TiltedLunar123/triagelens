import { describe, expect, it } from 'vitest'
import type { Finding } from '../../types'
import { SAMPLES } from '../../data/samples'
import { parseLogs } from '../parsers'
import { runDetections } from './rules'

function findingsFor(id: string): Finding[] {
  const sample = SAMPLES.find((s) => s.id === id)
  if (!sample) throw new Error(`sample ${id} not found`)
  return runDetections(parseLogs(sample.text))
}

const ids = (findings: Finding[]) => findings.map((f) => f.id)

describe('runDetections', () => {
  it('flags encoded PowerShell and event log clearing', () => {
    const findings = findingsFor('windows-encoded-powershell')
    expect(ids(findings)).toContain('encoded-powershell')
    expect(ids(findings)).toContain('clear-event-logs')

    const encoded = findings.find((f) => f.id === 'encoded-powershell')
    expect(encoded?.techniques.map((t) => t.id)).toContain('T1059.001')
  })

  it('flags the malicious document execution chain', () => {
    const findings = findingsFor('sysmon-malicious-doc')
    expect(ids(findings)).toContain('office-spawned-process')
    expect(ids(findings)).toContain('lolbin-execution')
  })

  it('flags brute force and the successful login that follows it', () => {
    const findings = findingsFor('ssh-brute-force')
    expect(ids(findings)).toContain('ssh-brute-force')

    const compromise = findings.find(
      (f) => f.id === 'successful-auth-after-brute-force',
    )
    expect(compromise?.severity).toBe('critical')
  })

  it('produces no findings for benign activity', () => {
    expect(findingsFor('benign-backup')).toHaveLength(0)
  })
})
