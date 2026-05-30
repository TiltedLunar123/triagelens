import { loadSettings } from '../settings'
import type { AnalysisProvider } from './provider'
import { coerceEnrichment } from './provider'

/**
 * Cloud provider backed by Claude. Requests go to the serverless function at
 * /api/analyze, which calls the Anthropic API. The key comes from the server
 * env by default; a bring-your-own-key from Provider setup is forwarded to the
 * function over HTTPS. Run `netlify dev` locally (or deploy to Netlify) for
 * this provider to work.
 */
export const anthropicProvider: AnalysisProvider = {
  id: 'anthropic',
  label: 'Claude (cloud, via serverless)',
  async enrich(request) {
    const { anthropicKey, anthropicModel } = loadSettings()
    let response: Response
    try {
      response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          riskScore: request.riskScore,
          severity: request.severity,
          findings: request.findings,
          events: request.events.slice(0, 25),
          apiKey: anthropicKey || undefined,
          model: anthropicModel || undefined,
        }),
      })
    } catch {
      throw new Error('Could not reach /api/analyze. Run the app with `netlify dev`.')
    }

    if (!response.ok) {
      const detail = await response.json().catch(() => ({}) as { error?: string })
      throw new Error(detail.error ?? `Analysis function returned ${response.status}.`)
    }

    const data = await response.json()
    return coerceEnrichment(data, request)
  },
}
