import type { Finding, Severity } from '../types'
import { MitreBadge } from './MitreBadge'
import { SeverityPill } from './SeverityPill'

const BORDER: Record<Severity, string> = {
  info: 'var(--sev-info)',
  low: 'var(--sev-low)',
  medium: 'var(--sev-medium)',
  high: 'var(--sev-high)',
  critical: 'var(--sev-critical)',
}

export function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article className="finding" style={{ borderLeftColor: BORDER[finding.severity] }}>
      <div className="finding-head">
        <SeverityPill severity={finding.severity} />
        <h3>{finding.title}</h3>
      </div>

      <p>{finding.description}</p>

      {finding.analystNote && <p className="note">{finding.analystNote}</p>}

      <div className="badges">
        {finding.techniques.map((t) => (
          <MitreBadge key={t.id} technique={t} />
        ))}
      </div>

      {finding.evidence.length > 0 && (
        <ul className="evidence">
          {finding.evidence.map((line, i) => (
            <li key={i}>{line}</li>
          ))}
        </ul>
      )}

      <p className="rec">
        <strong>Recommended action: </strong>
        {finding.recommendation}
      </p>
    </article>
  )
}
