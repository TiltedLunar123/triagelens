import type { TriageResult } from '../types'
import { runDetections } from './detections/rules'
import type { AnalysisProvider } from './llm/provider'
import { parseLogs } from './parsers'
import { maxSeverity, scoreRisk } from './risk'

/**
 * The full triage pipeline:
 *   raw text -> normalized events -> detections -> risk score -> AI enrichment.
 *
 * Parsing, detection, and scoring are deterministic and provider-independent.
 * Only the final narrative (summary, recommendations, notes) comes from the
 * selected AI provider, so the structured result is identical regardless of
 * which provider is chosen.
 */
export async function analyze(
  rawText: string,
  provider: AnalysisProvider,
): Promise<TriageResult> {
  const events = parseLogs(rawText)
  const findings = runDetections(events)
  const riskScore = scoreRisk(findings)
  const severity = maxSeverity(findings)

  const enrichment = await provider.enrich({ events, findings, riskScore, severity })

  const enrichedFindings = findings.map((finding) => ({
    ...finding,
    analystNote: enrichment.notes[finding.id],
  }))

  return {
    summary: enrichment.summary,
    recommendations: enrichment.recommendations,
    riskScore,
    severity,
    findings: enrichedFindings,
    events,
    generatedBy: provider.id,
    meta: {
      eventCount: events.length,
      analyzedAt: new Date().toISOString(),
    },
  }
}
