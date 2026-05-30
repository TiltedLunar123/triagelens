import { useState } from 'react'
import { ANTHROPIC_MODELS, type Settings } from '../lib/settings'

interface SettingsPanelProps {
  settings: Settings
  onSave: (settings: Settings) => void
  onClose: () => void
}

export function SettingsPanel({ settings, onSave, onClose }: SettingsPanelProps) {
  const [draft, setDraft] = useState<Settings>(settings)
  const [testResult, setTestResult] = useState<string | null>(null)
  const [testing, setTesting] = useState(false)

  async function testOllama() {
    setTesting(true)
    setTestResult(null)
    try {
      const res = await fetch(`${draft.ollamaUrl}/api/tags`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = (await res.json()) as { models?: Array<{ name?: string }> }
      const models = (data.models ?? []).map((m) => m.name ?? '')
      const hasModel = models.some((name) => name.startsWith(draft.ollamaModel))
      setTestResult(
        `Connected. ${models.length} model(s) installed.` +
          (hasModel
            ? ` "${draft.ollamaModel}" is available.`
            : ` Note: "${draft.ollamaModel}" is not pulled yet. Run: ollama pull ${draft.ollamaModel}`),
      )
    } catch {
      setTestResult(
        `Could not reach Ollama at ${draft.ollamaUrl}. Start it with "ollama serve" and check the URL.`,
      )
    } finally {
      setTesting(false)
    }
  }

  const keyLooksValid = draft.anthropicKey === '' || draft.anthropicKey.startsWith('sk-ant-')

  return (
    <div className="panel settings">
      <div className="settings-head">
        <div className="section-title">Provider setup</div>
        <button className="ghost" onClick={onClose}>
          Close
        </button>
      </div>

      <div className="settings-group">
        <h4>Local model (Ollama)</h4>
        <p className="muted small">
          Runs on your machine, so log data never leaves the host. Install from{' '}
          <a href="https://ollama.com" target="_blank" rel="noreferrer">
            ollama.com
          </a>
          , then pull a model.
        </p>
        <label className="field">
          Base URL
          <input
            value={draft.ollamaUrl}
            onChange={(e) => setDraft((d) => ({ ...d, ollamaUrl: e.target.value }))}
            placeholder="http://localhost:11434"
          />
        </label>
        <label className="field">
          Model
          <input
            value={draft.ollamaModel}
            onChange={(e) => setDraft((d) => ({ ...d, ollamaModel: e.target.value }))}
            placeholder="llama3.1"
          />
        </label>
        <button className="ghost" onClick={testOllama} disabled={testing}>
          {testing ? 'Testing...' : 'Test connection'}
        </button>
        {testResult && <p className="test-result small">{testResult}</p>}
      </div>

      <div className="settings-group">
        <h4>Claude (Anthropic API)</h4>
        <p className="muted small">
          Recommended: set <code>ANTHROPIC_API_KEY</code> as a server env var (see{' '}
          <code>.env.example</code>) and leave the key below blank. The field is an optional
          bring-your-own-key for trying the live demo. It is stored only in your browser and
          sent over HTTPS to the analysis function, never committed.
        </p>
        <label className="field">
          API key (optional)
          <input
            type="password"
            value={draft.anthropicKey}
            onChange={(e) => setDraft((d) => ({ ...d, anthropicKey: e.target.value }))}
            placeholder="sk-ant-...  (blank = use the server key)"
            autoComplete="off"
          />
        </label>
        {!keyLooksValid && (
          <p className="test-result small">
            That does not look like an Anthropic key. They start with sk-ant-.
          </p>
        )}
        <label className="field">
          Model
          <select
            value={draft.anthropicModel}
            onChange={(e) => setDraft((d) => ({ ...d, anthropicModel: e.target.value }))}
          >
            {ANTHROPIC_MODELS.map((m) => (
              <option key={m.id} value={m.id}>
                {m.label}
              </option>
            ))}
          </select>
        </label>
        <p className="muted small">
          The Claude provider needs the serverless function. Run locally with{' '}
          <code>netlify dev</code>, or deploy to Netlify.
        </p>
      </div>

      <div className="settings-actions">
        <button className="primary" onClick={() => onSave(draft)}>
          Save settings
        </button>
        <button className="ghost" onClick={() => setDraft({ ...settings })}>
          Reset
        </button>
      </div>
    </div>
  )
}
