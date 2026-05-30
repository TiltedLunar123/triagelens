import type { Finding, Severity } from '../types'

/** Severity ordered from lowest to highest. Useful for sorting and comparison. */
export const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical']

const SEVERITY_WEIGHT: Record<Severity, number> = {
  info: 0,
  low: 10,
  medium: 25,
  high: 45,
  critical: 70,
}

/**
 * Composite 0-100 risk score. The highest-severity finding contributes its full
 * weight; each additional finding adds a halved contribution so that stacking
 * many low findings cannot eclipse a single critical one, while still rewarding
 * corroborating evidence.
 */
export function scoreRisk(findings: Finding[]): number {
  if (findings.length === 0) return 0

  const sorted = [...findings].sort(
    (a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity],
  )

  let score = SEVERITY_WEIGHT[sorted[0].severity]
  for (let i = 1; i < sorted.length; i++) {
    score += SEVERITY_WEIGHT[sorted[i].severity] * Math.pow(0.5, i)
  }

  return Math.min(100, Math.round(score))
}

/** The highest severity among the findings, or "info" when there are none. */
export function maxSeverity(findings: Finding[]): Severity {
  let max: Severity = 'info'
  for (const finding of findings) {
    if (SEVERITY_ORDER.indexOf(finding.severity) > SEVERITY_ORDER.indexOf(max)) {
      max = finding.severity
    }
  }
  return max
}
