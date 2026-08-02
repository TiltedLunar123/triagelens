import type { Finding, MitreTechnique, NormalizedEvent, Severity } from '../../types'
import { techniques } from '../mitre/attack'

/**
 * A detection rule inspects the normalized events and returns evidence strings
 * for every match. An empty array means the rule did not fire. Keeping rules as
 * plain, pure functions makes them easy to unit test and reason about.
 */
export interface DetectionRule {
  id: string
  title: string
  severity: Severity
  description: string
  techniques: MitreTechnique[]
  recommendation: string
  detect: (events: NormalizedEvent[]) => string[]
}

const OFFICE_PARENTS = /winword|excel|powerpnt|outlook|onenote|mspub/i
const LOLBINS = /\b(mshta|certutil|regsvr32|rundll32|wmic|bitsadmin|cscript|wscript)\.exe\b/i
const TEMP_PATH = /\\(Temp|AppData\\Local\\Temp|Downloads)\\/i

/** Failed logons from one source address before it counts as brute force. */
const BRUTE_FORCE_THRESHOLD = 5
/** How close together those failures have to be. */
const BRUTE_FORCE_WINDOW_SECONDS = 10 * 60
const WINDOW_LABEL = '10 minutes'

export const RULES: DetectionRule[] = [
  {
    id: 'encoded-powershell',
    title: 'Obfuscated or encoded PowerShell',
    severity: 'high',
    description:
      'PowerShell was launched with an encoded command or evasion flags. Attackers use this to hide payloads from log review and casual inspection.',
    techniques: techniques('T1059.001', 'T1027'),
    recommendation:
      'Decode the -EncodedCommand payload, identify the script content, and isolate the host if the command is malicious.',
    detect: (events) =>
      events
        .filter(
          (e) =>
            e.commandLine !== undefined &&
            /(-enc(odedcommand)?\b|-e\s+[A-Za-z0-9+/=]{20,}|frombase64string|-nop\b.*-w\s+hidden|-windowstyle\s+hidden)/i.test(
              e.commandLine,
            ),
        )
        .map((e) => evidenceLine(e, e.commandLine)),
  },
  {
    id: 'office-spawned-process',
    title: 'Office application spawned a child process',
    severity: 'high',
    description:
      'A Microsoft Office process started another executable. This is a classic malicious-document execution chain, where a macro or exploit launches a payload.',
    techniques: techniques('T1566.001', 'T1204.002'),
    recommendation:
      'Retrieve the originating document, detonate it in a sandbox, and check mail gateway logs for other recipients.',
    detect: (events) =>
      events
        .filter(
          (e) =>
            e.parentProcess !== undefined &&
            OFFICE_PARENTS.test(e.parentProcess) &&
            e.process !== undefined,
        )
        .map((e) => evidenceLine(e, `${e.parentProcess} -> ${e.process}`)),
  },
  {
    id: 'lolbin-execution',
    title: 'Living-off-the-land binary executed',
    severity: 'medium',
    description:
      'A trusted system binary often abused by attackers (LOLBin) was executed. These tools can download files or proxy code execution while blending in.',
    techniques: techniques('T1218', 'T1105'),
    recommendation:
      'Review the full command line and arguments for remote URLs or scriptlets, and confirm whether the activity is expected for this host.',
    detect: (events) =>
      events
        .filter((e) => {
          const haystack = `${e.process ?? ''} ${e.commandLine ?? ''}`
          return LOLBINS.test(haystack)
        })
        .map((e) => evidenceLine(e, e.commandLine ?? e.process)),
  },
  {
    id: 'temp-dir-execution',
    title: 'Process executed from a temporary directory',
    severity: 'medium',
    description:
      'An executable ran from a Temp, AppData, or Downloads path. Legitimate software rarely runs from these locations, which are common staging grounds for malware.',
    techniques: techniques('T1059'),
    recommendation:
      'Hash the binary and check it against threat intelligence, then determine how it was written to disk.',
    detect: (events) =>
      events
        .filter((e) => {
          const path = String(e.raw?.EventData ? imagePath(e) : e.process ?? '')
          return TEMP_PATH.test(path) || TEMP_PATH.test(e.commandLine ?? '')
        })
        .map((e) => evidenceLine(e, imagePath(e) ?? e.process)),
  },
  {
    id: 'clear-event-logs',
    title: 'Windows event logs cleared',
    severity: 'high',
    description:
      'A command was issued to clear Windows event logs. This is a strong anti-forensics signal that often follows hands-on-keyboard activity.',
    techniques: techniques('T1070.001'),
    recommendation:
      'Treat as a likely active intrusion. Preserve remaining logs, check for prior suspicious activity, and begin incident response.',
    detect: (events) =>
      events
        .filter(
          (e) =>
            e.commandLine !== undefined &&
            /(wevtutil\s+cl|clear-eventlog|remove-item.+\.evtx)/i.test(e.commandLine),
        )
        .map((e) => evidenceLine(e, e.commandLine)),
  },
  {
    id: 'ssh-brute-force',
    title: 'SSH brute-force attempt',
    severity: 'high',
    description: `A single source address produced ${BRUTE_FORCE_THRESHOLD} or more failed SSH logons inside ${WINDOW_LABEL}, consistent with password guessing or credential stuffing.`,
    techniques: techniques('T1110'),
    recommendation:
      'Block the source IP, confirm no account was compromised, and enforce key-based authentication and rate limiting.',
    detect: (events) => {
      const evidence: string[] = []
      for (const [ip, times] of Object.entries(failureTimesByIp(events))) {
        const burst = peakBurst(times)
        if (burst.count < BRUTE_FORCE_THRESHOLD) continue
        evidence.push(
          burst.windowed
            ? `${burst.count} failed SSH logons from ${ip} within ${WINDOW_LABEL}`
            : `${burst.count} failed SSH logons from ${ip}`,
        )
      }
      return evidence
    },
  },
  {
    id: 'successful-auth-after-brute-force',
    title: 'Successful login after brute-force activity',
    severity: 'critical',
    description: `An IP authenticated successfully within ${WINDOW_LABEL} of producing ${BRUTE_FORCE_THRESHOLD} or more failed SSH logons. This pattern indicates a likely account compromise.`,
    techniques: techniques('T1110', 'T1078'),
    recommendation:
      'Treat the account as compromised: force a password reset, terminate active sessions, and hunt for post-access activity from this host.',
    detect: (events) => {
      const evidence: string[] = []
      // Collect failures as we walk the log so a success only sees the ones
      // that actually preceded it. Counting the whole file up front flags a
      // legitimate login that happened before an attacker ever showed up.
      const failuresSoFar: Record<string, (number | undefined)[]> = {}
      for (const e of events) {
        if (!e.sourceIp) continue
        if (e.eventId === 'auth-failure') {
          ;(failuresSoFar[e.sourceIp] ??= []).push(eventSeconds(e))
          continue
        }
        if (e.eventId !== 'auth-success') continue
        const prior = failuresSoFar[e.sourceIp] ?? []
        const runUp = failuresLeadingUpTo(prior, eventSeconds(e))
        if (runUp < BRUTE_FORCE_THRESHOLD) continue
        evidence.push(
          `Successful login for "${e.user}" from ${e.sourceIp} after ${runUp} failures`,
        )
      }
      return evidence
    },
  },
]

/** Run every rule and build a Finding for each rule that produced evidence. */
export function runDetections(events: NormalizedEvent[]): Finding[] {
  const findings: Finding[] = []
  for (const rule of RULES) {
    const evidence = rule.detect(events)
    if (evidence.length === 0) continue
    findings.push({
      id: rule.id,
      title: rule.title,
      severity: rule.severity,
      description: rule.description,
      evidence,
      techniques: rule.techniques,
      recommendation: rule.recommendation,
    })
  }
  return findings
}

// --- helpers ---------------------------------------------------------------

function evidenceLine(event: NormalizedEvent, detail?: string): string {
  const host = event.host ? `[${event.host}] ` : ''
  const user = event.user ? `${event.user}: ` : ''
  return `${host}${user}${detail ?? event.message}`.trim()
}

function imagePath(event: NormalizedEvent): string | undefined {
  const data = (event.raw?.EventData ?? {}) as Record<string, any>
  return data.Image ?? data.NewProcessName ?? event.process
}

function failureTimesByIp(
  events: NormalizedEvent[],
): Record<string, (number | undefined)[]> {
  const byIp: Record<string, (number | undefined)[]> = {}
  for (const e of events) {
    if (e.eventId === 'auth-failure' && e.sourceIp) {
      ;(byIp[e.sourceIp] ??= []).push(eventSeconds(e))
    }
  }
  return byIp
}

const SYSLOG_TIME = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/
const MONTHS = [
  'jan', 'feb', 'mar', 'apr', 'may', 'jun',
  'jul', 'aug', 'sep', 'oct', 'nov', 'dec',
]

/**
 * An event's time as whole seconds, or undefined when there is nothing usable
 * to read. Syslog lines carry no year, so those resolve against a fixed
 * reference year; that only ever gets compared against other events from the
 * same file, so the missing year does not matter. A log that crosses from
 * December into January is the one case this gets wrong, and the cost there is
 * a missed grouping rather than a false alarm.
 */
function eventSeconds(event: NormalizedEvent): number | undefined {
  const raw = event.timestamp?.trim()
  if (!raw) return undefined

  const syslog = SYSLOG_TIME.exec(raw)
  if (syslog) {
    const month = MONTHS.indexOf(syslog[1].toLowerCase())
    if (month === -1) return undefined
    return (
      Date.UTC(
        2000,
        month,
        Number(syslog[2]),
        Number(syslog[3]),
        Number(syslog[4]),
        Number(syslog[5]),
      ) / 1000
    )
  }

  const parsed = Date.parse(raw)
  return Number.isNaN(parsed) ? undefined : Math.floor(parsed / 1000)
}

/**
 * The most failures from one address that land inside a single window, plus
 * whether the window was actually applied. When any of the times cannot be
 * read there is no way to measure the spread, so the whole run counts and the
 * caller is told not to claim a window in its evidence.
 */
function peakBurst(times: (number | undefined)[]): {
  count: number
  windowed: boolean
} {
  if (times.some((t) => t === undefined)) {
    return { count: times.length, windowed: false }
  }
  const sorted = (times as number[]).slice().sort((a, b) => a - b)
  let best = 0
  let start = 0
  for (let end = 0; end < sorted.length; end++) {
    while (sorted[end] - sorted[start] > BRUTE_FORCE_WINDOW_SECONDS) start++
    best = Math.max(best, end - start + 1)
  }
  return { count: best, windowed: true }
}

/**
 * How many of the failures that preceded a login fall inside the window that
 * ends at it. Falls back to the plain count when either side has no readable
 * time.
 */
function failuresLeadingUpTo(
  priorFailures: (number | undefined)[],
  loginAt: number | undefined,
): number {
  if (loginAt === undefined) return priorFailures.length
  let count = 0
  for (const at of priorFailures) {
    if (at === undefined) {
      count++
      continue
    }
    if (loginAt - at <= BRUTE_FORCE_WINDOW_SECONDS) count++
  }
  return count
}
