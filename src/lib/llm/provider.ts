import type { Finding, NormalizedEvent, Severity } from '../../types'

/** What every provider receives: the parsed events plus rule-based findings. */
export interface EnrichmentRequest {
  events: NormalizedEvent[]
  findings: Finding[]
  riskScore: number
  severity: Severity
}

/**
 * What every provider returns. The structured detections come from code, so the
 * AI layer only contributes prose. That keeps the tool useful even when a model
 * returns imperfect output.
 */
export interface Enrichment {
  summary: string
  recommendations: string[]
  /** Map of finding id -> short analyst note. */
  notes: Record<string, string>
}

/** A pluggable analysis backend (demo, local Ollama, or cloud Claude). */
export interface AnalysisProvider {
  id: 'demo' | 'ollama' | 'anthropic'
  label: string
  /** Whether the provider can run without extra setup in the current context. */
  enrich: (request: EnrichmentRequest) => Promise<Enrichment>
}

/**
 * Defensively turn arbitrary parsed model output into an Enrichment. Missing or
 * malformed fields fall back to safe defaults so a bad response never throws.
 */
export function coerceEnrichment(
  value: unknown,
  request: EnrichmentRequest,
): Enrichment {
  const obj = (typeof value === 'object' && value !== null ? value : {}) as Record<
    string,
    unknown
  >

  const summary =
    typeof obj.summary === 'string' && obj.summary.trim().length > 0
      ? obj.summary.trim()
      : fallbackSummary(request)

  const recommendations = Array.isArray(obj.recommendations)
    ? obj.recommendations.filter((r): r is string => typeof r === 'string')
    : []

  const notes: Record<string, string> = {}
  if (obj.notes && typeof obj.notes === 'object') {
    for (const [key, val] of Object.entries(obj.notes as Record<string, unknown>)) {
      if (typeof val === 'string') notes[key] = val
    }
  }

  return {
    summary,
    recommendations:
      recommendations.length > 0 ? recommendations : fallbackRecommendations(request),
    notes,
  }
}

/** Parse a JSON string from a model, tolerating code fences and stray prose. */
export function parseJsonLoose(text: string): unknown {
  const trimmed = text.trim()
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i)
  const candidate = fenced ? fenced[1] : trimmed
  try {
    return JSON.parse(candidate)
  } catch {
    // Try to grab the outermost JSON object if the model added commentary.
    const start = candidate.indexOf('{')
    const end = candidate.lastIndexOf('}')
    if (start !== -1 && end > start) {
      try {
        return JSON.parse(candidate.slice(start, end + 1))
      } catch {
        return undefined
      }
    }
    return undefined
  }
}

export function fallbackSummary(request: EnrichmentRequest): string {
  if (request.findings.length === 0) {
    return `No suspicious activity matched the current detection rules across ${request.events.length} event(s).`
  }
  const titles = request.findings.map((f) => f.title).join('; ')
  return `${request.findings.length} finding(s) across ${request.events.length} event(s). Highest severity: ${request.severity}. Risk score ${request.riskScore}/100. Notable activity: ${titles}.`
}

export function fallbackRecommendations(request: EnrichmentRequest): string[] {
  if (request.findings.length === 0) {
    return ['No action required. Continue normal monitoring.']
  }
  // De-duplicate the per-rule recommendations, highest severity first.
  const seen = new Set<string>()
  const recs: string[] = []
  for (const finding of request.findings) {
    if (!seen.has(finding.recommendation)) {
      seen.add(finding.recommendation)
      recs.push(finding.recommendation)
    }
  }
  return recs
}
