import type { Severity } from '../types'

export function SeverityPill({ severity }: { severity: Severity }) {
  return <span className={`pill pill-${severity}`}>{severity}</span>
}
