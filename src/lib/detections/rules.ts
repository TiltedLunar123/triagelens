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
    description:
      'A single source address produced many failed SSH logons in a short window, consistent with password guessing or credential stuffing.',
    techniques: techniques('T1110'),
    recommendation:
      'Block the source IP, confirm no account was compromised, and enforce key-based authentication and rate limiting.',
    detect: (events) => {
      const failsByIp = countFailuresByIp(events)
      return Object.entries(failsByIp)
        .filter(([, count]) => count >= 5)
        .map(([ip, count]) => `${count} failed SSH logons from ${ip}`)
    },
  },
  {
    id: 'successful-auth-after-brute-force',
    title: 'Successful login after brute-force activity',
    severity: 'critical',
    description:
      'An IP that generated many failed SSH logons then authenticated successfully. This pattern indicates a likely account compromise.',
    techniques: techniques('T1110', 'T1078'),
    recommendation:
      'Treat the account as compromised: force a password reset, terminate active sessions, and hunt for post-access activity from this host.',
    detect: (events) => {
      const failsByIp = countFailuresByIp(events)
      const evidence: string[] = []
      for (const e of events) {
        if (
          e.eventId === 'auth-success' &&
          e.sourceIp &&
          (failsByIp[e.sourceIp] ?? 0) >= 5
        ) {
          evidence.push(
            `Successful login for "${e.user}" from ${e.sourceIp} after ${failsByIp[e.sourceIp]} failures`,
          )
        }
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

function countFailuresByIp(events: NormalizedEvent[]): Record<string, number> {
  const counts: Record<string, number> = {}
  for (const e of events) {
    if (e.eventId === 'auth-failure' && e.sourceIp) {
      counts[e.sourceIp] = (counts[e.sourceIp] ?? 0) + 1
    }
  }
  return counts
}
