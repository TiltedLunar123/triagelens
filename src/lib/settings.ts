// User-configurable provider settings, persisted to localStorage so they
// survive reloads. The providers read these at analysis time, which keeps the
// configuration in one place and out of the call sites.

export interface Settings {
  ollamaUrl: string
  ollamaModel: string
  /** Optional bring-your-own-key. Stored only in the browser; may be empty to
   *  fall back to the server-side ANTHROPIC_API_KEY. */
  anthropicKey: string
  anthropicModel: string
}

const STORAGE_KEY = 'triagelens.settings'

export const DEFAULT_SETTINGS: Settings = {
  ollamaUrl: (import.meta.env.VITE_OLLAMA_URL as string | undefined) || 'http://localhost:11434',
  ollamaModel: (import.meta.env.VITE_OLLAMA_MODEL as string | undefined) || 'llama3.1',
  anthropicKey: '',
  anthropicModel: 'claude-haiku-4-5',
}

export const ANTHROPIC_MODELS = [
  { id: 'claude-haiku-4-5', label: 'Claude Haiku 4.5 (fast, low cost)' },
  { id: 'claude-sonnet-4-6', label: 'Claude Sonnet 4.6 (balanced)' },
  { id: 'claude-opus-4-8', label: 'Claude Opus 4.8 (most capable)' },
]

/** Fill in and type-coerce a partial or untrusted settings object. */
export function mergeSettings(raw: unknown): Settings {
  const r = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>
  const str = (value: unknown, fallback: string) =>
    typeof value === 'string' && value.trim().length > 0 ? value.trim() : fallback

  return {
    ollamaUrl: str(r.ollamaUrl, DEFAULT_SETTINGS.ollamaUrl),
    ollamaModel: str(r.ollamaModel, DEFAULT_SETTINGS.ollamaModel),
    // The key may legitimately be empty (use the server env key), so keep it as-is.
    anthropicKey:
      typeof r.anthropicKey === 'string' ? r.anthropicKey.trim() : DEFAULT_SETTINGS.anthropicKey,
    anthropicModel: str(r.anthropicModel, DEFAULT_SETTINGS.anthropicModel),
  }
}

export function loadSettings(): Settings {
  if (typeof localStorage === 'undefined') return { ...DEFAULT_SETTINGS }
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    return stored ? mergeSettings(JSON.parse(stored)) : { ...DEFAULT_SETTINGS }
  } catch {
    return { ...DEFAULT_SETTINGS }
  }
}

export function saveSettings(settings: Settings): void {
  if (typeof localStorage === 'undefined') return
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings))
  } catch {
    // Storage can be unavailable (private mode, quota). Ignore and keep in memory.
  }
}
