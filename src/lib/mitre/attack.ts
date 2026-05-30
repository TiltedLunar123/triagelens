import type { MitreTechnique } from '../../types'

/**
 * A curated subset of MITRE ATT&CK (Enterprise) techniques relevant to the
 * detection rules shipped with TriageLens. This is intentionally small and
 * hand-maintained rather than the full framework, so mappings stay accurate
 * and reviewable. Add entries here as new detection rules are written.
 */
type TechniqueSeed = Omit<MitreTechnique, 'url'>

const TECHNIQUE_SEEDS: Record<string, TechniqueSeed> = {
  'T1059': { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
  'T1059.001': { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution' },
  'T1027': { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'Defense Evasion' },
  'T1204.002': { id: 'T1204.002', name: 'User Execution: Malicious File', tactic: 'Execution' },
  'T1566.001': { id: 'T1566.001', name: 'Phishing: Spearphishing Attachment', tactic: 'Initial Access' },
  'T1218': { id: 'T1218', name: 'System Binary Proxy Execution', tactic: 'Defense Evasion' },
  'T1105': { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control' },
  'T1110': { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
  'T1078': { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' },
  'T1070.001': { id: 'T1070.001', name: 'Indicator Removal: Clear Windows Event Logs', tactic: 'Defense Evasion' },
}

/** Build the canonical attack.mitre.org URL for a technique id. */
function techniqueUrl(id: string): string {
  // "T1059.001" -> "T1059/001", "T1059" -> "T1059"
  return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`
}

/**
 * Resolve a technique id to a full MitreTechnique. Unknown ids degrade
 * gracefully so a new rule referencing a missing id never crashes the report.
 */
export function technique(id: string): MitreTechnique {
  const seed = TECHNIQUE_SEEDS[id]
  if (seed) {
    return { ...seed, url: techniqueUrl(id) }
  }
  return { id, name: id, tactic: 'Unknown', url: techniqueUrl(id) }
}

/** Convenience helper for rules that reference several techniques at once. */
export function techniques(...ids: string[]): MitreTechnique[] {
  return ids.map(technique)
}
