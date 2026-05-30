// Core domain types shared across the parsing, detection, and AI layers.

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export type LogSource =
  | 'windows-security'
  | 'sysmon'
  | 'auth'
  | 'json'
  | 'raw'

/**
 * A single security event after parsing and normalization. Parsers map their
 * native fields onto this shape so that detection rules only deal with one
 * vocabulary, regardless of the original log format.
 */
export interface NormalizedEvent {
  id: string
  timestamp?: string
  source: LogSource
  eventId?: string | number
  host?: string
  user?: string
  process?: string
  parentProcess?: string
  commandLine?: string
  sourceIp?: string
  destIp?: string
  message: string
  /** The original record, kept for evidence display and debugging. */
  raw: Record<string, unknown>
}

/** A MITRE ATT&CK technique reference attached to a finding. */
export interface MitreTechnique {
  /** e.g. "T1059.001" */
  id: string
  /** e.g. "PowerShell" */
  name: string
  /** e.g. "Execution" */
  tactic: string
  /** Link to the technique page on attack.mitre.org */
  url: string
}

/** One thing worth an analyst's attention, produced by a detection rule. */
export interface Finding {
  id: string
  title: string
  severity: Severity
  description: string
  /** Concrete evidence lines pulled from the events that triggered the rule. */
  evidence: string[]
  techniques: MitreTechnique[]
  recommendation: string
  /** Optional natural-language note added by an AI provider. */
  analystNote?: string
}

/** The full triage result rendered in the report. */
export interface TriageResult {
  summary: string
  recommendations: string[]
  /** 0-100 composite risk score. */
  riskScore: number
  severity: Severity
  findings: Finding[]
  events: NormalizedEvent[]
  generatedBy: 'demo' | 'ollama' | 'anthropic'
  meta: {
    eventCount: number
    analyzedAt: string
  }
}
