import { SAMPLES } from '../data/samples'
import { PROVIDERS, type ProviderId } from '../lib/llm/registry'

interface LogInputProps {
  value: string
  onChange: (value: string) => void
  providerId: ProviderId
  onProviderChange: (id: ProviderId) => void
  onLoadSample: (text: string) => void
  onAnalyze: () => void
  onClear: () => void
  loading: boolean
}

export function LogInput({
  value,
  onChange,
  providerId,
  onProviderChange,
  onLoadSample,
  onAnalyze,
  onClear,
  loading,
}: LogInputProps) {
  return (
    <div className="panel">
      <div className="controls">
        <label className="field">
          Load a sample
          <select
            defaultValue=""
            onChange={(e) => {
              const sample = SAMPLES.find((s) => s.id === e.target.value)
              if (sample) onLoadSample(sample.text)
            }}
          >
            <option value="" disabled>
              Choose a sample log...
            </option>
            {SAMPLES.map((s) => (
              <option key={s.id} value={s.id}>
                {s.label}
              </option>
            ))}
          </select>
        </label>

        <label className="field">
          Analysis provider
          <select
            value={providerId}
            onChange={(e) => onProviderChange(e.target.value as ProviderId)}
          >
            {PROVIDERS.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
        </label>

        <button className="primary" onClick={onAnalyze} disabled={loading || !value.trim()}>
          {loading ? 'Analyzing...' : 'Analyze'}
        </button>
        <button className="ghost" onClick={onClear} disabled={loading}>
          Clear
        </button>
      </div>

      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Paste raw logs here: Windows Security / Sysmon JSON, a SIEM JSON export, or a Linux auth.log. Or load a sample above."
        spellCheck={false}
      />
    </div>
  )
}
