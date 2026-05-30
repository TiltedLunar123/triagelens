import type { NormalizedEvent } from '../../types'
import { parseAuthLog } from './auth'
import { parseGenericJson } from './genericJson'
import { parseSysmon } from './sysmon'
import { parseWindowsSecurity } from './windowsSecurity'

/**
 * Detect the log format and parse raw text into normalized events.
 *
 * Detection order:
 *   1. JSON object or array  -> route each record by its Provider / EventID
 *   2. SSH syslog lines      -> auth log parser
 *   3. Anything else         -> one raw event per non-empty line
 */
export function parseLogs(input: string): NormalizedEvent[] {
  const text = input.trim()
  if (!text) return []

  if (text.startsWith('{') || text.startsWith('[')) {
    const parsed = tryParseJson(text)
    if (parsed !== undefined) {
      const records = Array.isArray(parsed) ? parsed : [parsed]
      return records.flatMap((record, index) => routeJsonRecord(record, index))
    }
  }

  if (/sshd\[|Failed password|Accepted (password|publickey)/i.test(text)) {
    return parseAuthLog(text)
  }

  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line, index) => ({
      id: `raw-${index}`,
      source: 'raw' as const,
      message: line,
      raw: { line },
    }))
}

function tryParseJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return undefined
  }
}

function routeJsonRecord(record: unknown, index: number): NormalizedEvent[] {
  if (typeof record !== 'object' || record === null) return []
  const r = record as Record<string, any>
  const provider = String(r.Provider ?? r.provider ?? r.SourceName ?? '')

  if (/sysmon/i.test(provider)) return [parseSysmon(r, index)]
  if (/security-auditing|security/i.test(provider) || r.EventID === 4688) {
    return [parseWindowsSecurity(r, index)]
  }
  return [parseGenericJson(r, index)]
}
