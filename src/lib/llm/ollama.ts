import { loadSettings } from '../settings'
import type { AnalysisProvider } from './provider'
import { coerceEnrichment, parseJsonLoose } from './provider'
import { SYSTEM_PROMPT, buildUserPrompt } from './prompt'

/**
 * Local provider backed by Ollama (https://ollama.com). Runs entirely on the
 * user's machine, so log data never leaves the host. The base URL and model
 * come from Provider setup (or VITE_OLLAMA_* defaults). Requires Ollama to be
 * running with a pulled model, for example: `ollama pull llama3.1`.
 */
export const ollamaProvider: AnalysisProvider = {
  id: 'ollama',
  label: 'Local model (Ollama)',
  async enrich(request) {
    const { ollamaUrl, ollamaModel } = loadSettings()
    let response: Response
    try {
      response = await fetch(`${ollamaUrl}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: ollamaModel,
          stream: false,
          format: 'json',
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            { role: 'user', content: buildUserPrompt(request) },
          ],
        }),
      })
    } catch {
      throw new Error(
        `Could not reach Ollama at ${ollamaUrl}. Is it running? Try: ollama serve`,
      )
    }

    if (!response.ok) {
      throw new Error(`Ollama returned ${response.status}. Check the model name (${ollamaModel}).`)
    }

    const data = (await response.json()) as { message?: { content?: string } }
    const content = data.message?.content ?? ''
    return coerceEnrichment(parseJsonLoose(content), request)
  },
}
