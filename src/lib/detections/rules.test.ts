import { describe, expect, it } from 'vitest'
import type { Finding, NormalizedEvent } from '../../types'
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

// --- SSH ordering ----------------------------------------------------------

let port = 50000

/** One syslog line at HH:MM:SS on May 28. */
function fail(time: string, ip: string, user = 'root'): string {
  return `May 28 ${time} web01 sshd[${port++}]: Failed password for ${user} from ${ip} port ${port} ssh2`
}

function ok(time: string, ip: string, user = 'deploy'): string {
  return `May 28 ${time} web01 sshd[${port++}]: Accepted password for ${user} from ${ip} port ${port} ssh2`
}

const detect = (lines: string[]) => runDetections(parseLogs(lines.join('\n')))

describe('successful-auth-after-brute-force', () => {
  it('ignores a login that happened before the failures started', () => {
    const findings = detect([
      ok('08:00:01', '10.0.0.5'),
      fail('09:00:02', '10.0.0.5'),
      fail('09:00:03', '10.0.0.5'),
      fail('09:00:04', '10.0.0.5'),
      fail('09:00:05', '10.0.0.5'),
      fail('09:00:06', '10.0.0.5'),
    ])

    // The guessing itself is still worth flagging, the compromise is not.
    expect(ids(findings)).toContain('ssh-brute-force')
    expect(ids(findings)).not.toContain('successful-auth-after-brute-force')
  })

  it('fires when the login follows enough failures', () => {
    const findings = detect([
      fail('09:00:01', '10.0.0.5'),
      fail('09:00:02', '10.0.0.5'),
      fail('09:00:03', '10.0.0.5'),
      fail('09:00:04', '10.0.0.5'),
      fail('09:00:05', '10.0.0.5'),
      ok('09:00:06', '10.0.0.5'),
    ])

    const compromise = findings.find(
      (f) => f.id === 'successful-auth-after-brute-force',
    )
    expect(compromise?.severity).toBe('critical')
    expect(compromise?.evidence).toEqual([
      'Successful login for "deploy" from 10.0.0.5 after 5 failures',
    ])
  })

  it('counts only the failures before the login, not the ones after', () => {
    const findings = detect([
      fail('09:00:01', '10.0.0.5'),
      fail('09:00:02', '10.0.0.5'),
      fail('09:00:03', '10.0.0.5'),
      fail('09:00:04', '10.0.0.5'),
      ok('09:00:05', '10.0.0.5'),
      fail('09:00:06', '10.0.0.5'),
      fail('09:00:07', '10.0.0.5'),
    ])

    // Six failures overall, but only four came first, so this is not a
    // post-brute-force login.
    expect(ids(findings)).toContain('ssh-brute-force')
    expect(ids(findings)).not.toContain('successful-auth-after-brute-force')
  })

  it('does not borrow failures from another source address', () => {
    const findings = detect([
      fail('09:00:01', '10.0.0.9'),
      fail('09:00:02', '10.0.0.9'),
      fail('09:00:03', '10.0.0.9'),
      fail('09:00:04', '10.0.0.9'),
      fail('09:00:05', '10.0.0.9'),
      ok('09:00:06', '10.0.0.5'),
    ])

    expect(ids(findings)).not.toContain('successful-auth-after-brute-force')
  })

  it('ignores a login hours after the guessing stopped', () => {
    const findings = detect([
      fail('09:00:01', '10.0.0.5'),
      fail('09:00:02', '10.0.0.5'),
      fail('09:00:03', '10.0.0.5'),
      fail('09:00:04', '10.0.0.5'),
      fail('09:00:05', '10.0.0.5'),
      ok('12:00:00', '10.0.0.5'),
    ])

    expect(ids(findings)).toContain('ssh-brute-force')
    expect(ids(findings)).not.toContain('successful-auth-after-brute-force')
  })
})

// --- brute-force window ----------------------------------------------------

const bruteForce = (lines: string[]) =>
  detect(lines).find((f) => f.id === 'ssh-brute-force')

describe('ssh-brute-force window', () => {
  it('does not fire on failures spread across the day', () => {
    expect(
      bruteForce([
        fail('01:00:00', '10.0.0.5'),
        fail('05:00:00', '10.0.0.5'),
        fail('09:00:00', '10.0.0.5'),
        fail('14:00:00', '10.0.0.5'),
        fail('20:00:00', '10.0.0.5'),
      ]),
    ).toBeUndefined()
  })

  it('fires and says so when the failures are bunched together', () => {
    expect(
      bruteForce([
        fail('09:00:01', '10.0.0.5'),
        fail('09:02:00', '10.0.0.5'),
        fail('09:04:00', '10.0.0.5'),
        fail('09:06:00', '10.0.0.5'),
        fail('09:08:00', '10.0.0.5'),
      ])?.evidence,
    ).toEqual(['5 failed SSH logons from 10.0.0.5 within 10 minutes'])
  })

  it('counts the burst, not the stragglers around it', () => {
    // Two lone attempts in the morning, then a real run at 22:00.
    expect(
      bruteForce([
        fail('06:00:00', '10.0.0.5'),
        fail('13:00:00', '10.0.0.5'),
        fail('22:00:01', '10.0.0.5'),
        fail('22:00:02', '10.0.0.5'),
        fail('22:00:03', '10.0.0.5'),
        fail('22:00:04', '10.0.0.5'),
        fail('22:00:05', '10.0.0.5'),
      ])?.evidence,
    ).toEqual(['5 failed SSH logons from 10.0.0.5 within 10 minutes'])
  })

  it('falls back to a plain count when the times cannot be read', () => {
    const untimed: NormalizedEvent[] = Array.from({ length: 5 }, (_, i) => ({
      id: `f${i}`,
      source: 'json',
      eventId: 'auth-failure',
      sourceIp: '10.0.0.5',
      message: 'failed login',
      raw: {},
    }))

    const finding = runDetections(untimed).find((f) => f.id === 'ssh-brute-force')
    expect(finding?.evidence).toEqual(['5 failed SSH logons from 10.0.0.5'])
  })
})
