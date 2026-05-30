import { describe, expect, it } from 'vitest'
import { SAMPLES } from '../../data/samples'
import { parseLogs } from './index'

function sampleText(id: string): string {
  const sample = SAMPLES.find((s) => s.id === id)
  if (!sample) throw new Error(`sample ${id} not found`)
  return sample.text
}

describe('parseLogs', () => {
  it('parses Windows Security JSON into normalized events', () => {
    const events = parseLogs(sampleText('windows-encoded-powershell'))
    expect(events).toHaveLength(2)
    expect(events[0].source).toBe('windows-security')
    expect(events[0].process).toBe('powershell.exe')
    expect(events[0].commandLine).toContain('-enc')
  })

  it('parses Sysmon JSON and resolves the parent process name', () => {
    const events = parseLogs(sampleText('sysmon-malicious-doc'))
    expect(events[0].source).toBe('sysmon')
    expect(events[0].parentProcess).toBe('WINWORD.EXE')
  })

  it('parses an SSH auth log into failure and success events', () => {
    const events = parseLogs(sampleText('ssh-brute-force'))
    const failures = events.filter((e) => e.eventId === 'auth-failure')
    const successes = events.filter((e) => e.eventId === 'auth-success')
    expect(failures.length).toBeGreaterThanOrEqual(5)
    expect(successes).toHaveLength(1)
    expect(events.every((e) => e.sourceIp === '198.51.100.23')).toBe(true)
  })

  it('returns an empty array for empty input', () => {
    expect(parseLogs('   ')).toEqual([])
  })

  it('falls back to one raw event per line for unknown formats', () => {
    const events = parseLogs('line one\nline two')
    expect(events).toHaveLength(2)
    expect(events[0].source).toBe('raw')
  })
})
