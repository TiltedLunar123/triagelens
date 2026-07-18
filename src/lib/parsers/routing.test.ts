import { describe, expect, it } from 'vitest'
import { parseLogs } from './index'

// The sample-driven tests in parsers.test.ts cover the happy path for each
// format. These focus on the dispatcher itself: how parseLogs decides which
// parser a record goes to, and how it degrades when the input is malformed.

describe('parseLogs JSON routing', () => {
  it('routes an unknown-provider JSON object to the generic parser', () => {
    const events = parseLogs(
      JSON.stringify({
        timestamp: '2026-07-18T00:00:00Z',
        process: '/usr/bin/curl',
        user: 'root',
        src_ip: '203.0.113.9',
        message: 'outbound connection',
      }),
    )
    expect(events).toHaveLength(1)
    expect(events[0].source).toBe('json')
    expect(events[0].process).toBe('curl')
    expect(events[0].user).toBe('root')
    expect(events[0].sourceIp).toBe('203.0.113.9')
    expect(events[0].message).toBe('outbound connection')
  })

  it('falls back to the stringified record when a generic JSON log has no message', () => {
    const events = parseLogs(JSON.stringify({ action: 'blocked' }))
    expect(events[0].source).toBe('json')
    expect(events[0].message).toBe('{"action":"blocked"}')
  })

  it('routes EventID 4688 with no Provider to the Windows Security parser', () => {
    const events = parseLogs(
      JSON.stringify({
        EventID: 4688,
        EventData: {
          NewProcessName: 'C:\\Windows\\System32\\cmd.exe',
          CommandLine: 'cmd /c whoami',
        },
      }),
    )
    expect(events[0].source).toBe('windows-security')
    expect(events[0].process).toBe('cmd.exe')
    expect(events[0].commandLine).toBe('cmd /c whoami')
  })

  it('recognizes a lowercase provider alias for Windows Security', () => {
    const events = parseLogs(
      JSON.stringify({
        provider: 'Microsoft-Windows-Security-Auditing',
        EventData: { NewProcessName: 'powershell.exe' },
      }),
    )
    expect(events[0].source).toBe('windows-security')
    expect(events[0].process).toBe('powershell.exe')
  })

  it('recognizes the SourceName alias for Sysmon', () => {
    const events = parseLogs(
      JSON.stringify({
        SourceName: 'Microsoft-Windows-Sysmon',
        EventData: { Image: 'C:\\Windows\\System32\\cmd.exe' },
      }),
    )
    expect(events[0].source).toBe('sysmon')
    expect(events[0].process).toBe('cmd.exe')
  })

  it('handles a JSON array, dropping entries that are not objects', () => {
    const events = parseLogs(
      JSON.stringify([{ message: 'first' }, 42, null, { message: 'second' }]),
    )
    expect(events).toHaveLength(2)
    expect(events.map((e) => e.message)).toEqual(['first', 'second'])
    expect(events.every((e) => e.source === 'json')).toBe(true)
  })
})

describe('parseLogs fallbacks', () => {
  it('treats malformed JSON as raw text instead of throwing', () => {
    const events = parseLogs('{ this is not valid json')
    expect(events).toHaveLength(1)
    expect(events[0].source).toBe('raw')
    expect(events[0].message).toBe('{ this is not valid json')
  })

  it('splits CRLF raw input the same as LF', () => {
    const events = parseLogs('alpha\r\nbeta\r\n')
    expect(events).toHaveLength(2)
    expect(events.map((e) => e.message)).toEqual(['alpha', 'beta'])
    expect(events.every((e) => e.source === 'raw')).toBe(true)
  })
})
