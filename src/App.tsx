import { useState } from 'react'
import { AnalysisReport } from './components/AnalysisReport'
import { LogInput } from './components/LogInput'
import { SettingsPanel } from './components/SettingsPanel'
import { SAMPLES } from './data/samples'
import { analyze } from './lib/analyze'
import { getProvider, type ProviderId } from './lib/llm/registry'
import { loadSettings, saveSettings, type Settings } from './lib/settings'
import type { TriageResult } from './types'

export default function App() {
  const [input, setInput] = useState(SAMPLES[0].text)
  const [providerId, setProviderId] = useState<ProviderId>('demo')
  const [result, setResult] = useState<TriageResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [settings, setSettings] = useState<Settings>(loadSettings)
  const [showSettings, setShowSettings] = useState(false)

  async function runAnalysis() {
    setLoading(true)
    setError(null)
    try {
      const triage = await analyze(input, getProvider(providerId))
      setResult(triage)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed.')
    } finally {
      setLoading(false)
    }
  }

  function clear() {
    setInput('')
    setResult(null)
    setError(null)
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="app-title">
          <h1>
            <span className="logo">{'>'}_</span> TriageLens
          </h1>
          <span className="tagline">AI-assisted SOC alert and log triage</span>
        </div>
        <button
          className="ghost settings-toggle"
          onClick={() => setShowSettings((open) => !open)}
        >
          {showSettings ? 'Close setup' : 'Provider setup'}
        </button>
      </header>

      <LogInput
        value={input}
        onChange={setInput}
        providerId={providerId}
        onProviderChange={setProviderId}
        onLoadSample={(text) => {
          setInput(text)
          setResult(null)
          setError(null)
        }}
        onAnalyze={runAnalysis}
        onClear={clear}
        loading={loading}
      />

      {showSettings && (
        <SettingsPanel
          settings={settings}
          onSave={(next) => {
            saveSettings(next)
            setSettings(next)
            setShowSettings(false)
          }}
          onClose={() => setShowSettings(false)}
        />
      )}

      {error && (
        <div className="panel error">
          <strong>Could not analyze:</strong> {error}
        </div>
      )}

      {result && <AnalysisReport result={result} />}
    </div>
  )
}
