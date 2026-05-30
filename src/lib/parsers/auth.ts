import type { NormalizedEvent } from '../../types'

const FAILED = /(\w{3}\s+\d+\s[\d:]+)\s+(\S+)\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from ([\d.]+)/i
const ACCEPTED = /(\w{3}\s+\d+\s[\d:]+)\s+(\S+)\s+sshd\[\d+\]:\s+Accepted (?:password|publickey) for (\S+) from ([\d.]+)/i

/**
 * Parse a Linux SSH auth log (syslog format). Produces one normalized event
 * per accepted or failed authentication line; other lines are ignored.
 */
export function parseAuthLog(text: string): NormalizedEvent[] {
  const events: NormalizedEvent[] = []
  const lines = text.split(/\r?\n/)

  lines.forEach((line, index) => {
    const failed = FAILED.exec(line)
    if (failed) {
      const [, time, host, user, ip] = failed
      events.push({
        id: `auth-fail-${index}`,
        timestamp: time,
        source: 'auth',
        eventId: 'auth-failure',
        host,
        user,
        sourceIp: ip,
        message: line.trim(),
        raw: { line, outcome: 'failure' },
      })
      return
    }

    const accepted = ACCEPTED.exec(line)
    if (accepted) {
      const [, time, host, user, ip] = accepted
      events.push({
        id: `auth-ok-${index}`,
        timestamp: time,
        source: 'auth',
        eventId: 'auth-success',
        host,
        user,
        sourceIp: ip,
        message: line.trim(),
        raw: { line, outcome: 'success' },
      })
    }
  })

  return events
}
