import type { AnalysisProvider } from './provider'
import { fallbackRecommendations, fallbackSummary } from './provider'

/**
 * The default provider. It needs no API key, no network, and no local model.
 * It turns the rule-based findings into a readable summary and notes, so the
 * tool produces a full report out of the box. The richer Ollama and Claude
 * providers replace this prose with model-generated analysis.
 */
export const demoProvider: AnalysisProvider = {
  id: 'demo',
  label: 'Demo (rule-based, no AI)',
  async enrich(request) {
    const notes: Record<string, string> = {}
    for (const finding of request.findings) {
      const tactics = [...new Set(finding.techniques.map((t) => t.tactic))].join(', ')
      notes[finding.id] = `${finding.description} Mapped tactics: ${tactics || 'n/a'}.`
    }

    return {
      summary: fallbackSummary(request),
      recommendations: fallbackRecommendations(request),
      notes,
    }
  },
}
