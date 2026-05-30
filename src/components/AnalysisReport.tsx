import type { Severity, TriageResult } from '../types'
import { EventTable } from './EventTable'
import { FindingCard } from './FindingCard'
import { SeverityPill } from './SeverityPill'

const GAUGE_COLOR: Record<Severity, string> = {
  info: 'var(--sev-info)',
  low: 'var(--sev-low)',
  medium: 'var(--sev-medium)',
  high: 'var(--sev-high)',
  critical: 'var(--sev-critical)',
}

const PROVIDER_LABEL: Record<TriageResult['generatedBy'], string> = {
  demo: 'rule-based',
  ollama: 'local model',
  anthropic: 'claude',
}

export function AnalysisReport({ result }: { result: TriageResult }) {
  const color = GAUGE_COLOR[result.severity]

  return (
    <div>
      <div className="panel summary">
        <div
          className="gauge"
          style={{ border: `4px solid ${color}`, color }}
        >
          {result.riskScore}
          <span className="label">RISK</span>
        </div>
        <div>
          <div className="summary-meta">
            <SeverityPill severity={result.severity} />
            <span className="provider-tag">analysis: {PROVIDER_LABEL[result.generatedBy]}</span>
            <span className="provider-tag">{result.meta.eventCount} events</span>
            <span className="provider-tag">{result.findings.length} findings</span>
          </div>
          <p className="summary-text">{result.summary}</p>
        </div>
      </div>

      {result.recommendations.length > 0 && (
        <div className="panel">
          <div className="section-title">Recommended actions</div>
          <ol className="recs-list">
            {result.recommendations.map((rec, i) => (
              <li key={i} className="rec">
                {rec}
              </li>
            ))}
          </ol>
        </div>
      )}

      {result.findings.length > 0 ? (
        <>
          <div className="section-title">
            Findings ({result.findings.length})
          </div>
          {result.findings.map((finding) => (
            <FindingCard key={finding.id} finding={finding} />
          ))}
        </>
      ) : (
        <div className="panel">
          <p className="muted">
            No detection rules fired on these events. Review the parsed events below
            to confirm nothing was missed.
          </p>
        </div>
      )}

      <div className="panel">
        <EventTable events={result.events} />
      </div>
    </div>
  )
}
