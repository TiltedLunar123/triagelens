import type { AnalysisProvider } from './provider'
import { anthropicProvider } from './anthropic'
import { demoProvider } from './demo'
import { ollamaProvider } from './ollama'

export type ProviderId = AnalysisProvider['id']

/** All available providers, in display order. Demo is the default. */
export const PROVIDERS: AnalysisProvider[] = [
  demoProvider,
  ollamaProvider,
  anthropicProvider,
]

export function getProvider(id: ProviderId): AnalysisProvider {
  return PROVIDERS.find((p) => p.id === id) ?? demoProvider
}
