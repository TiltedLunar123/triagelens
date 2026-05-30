import { describe, expect, it } from 'vitest'
import { DEFAULT_SETTINGS, mergeSettings } from './settings'

describe('mergeSettings', () => {
  it('returns defaults for empty or invalid input', () => {
    expect(mergeSettings(null)).toEqual(DEFAULT_SETTINGS)
    expect(mergeSettings({})).toEqual(DEFAULT_SETTINGS)
    expect(mergeSettings('not an object')).toEqual(DEFAULT_SETTINGS)
  })

  it('overrides provided fields and keeps defaults for the rest', () => {
    const merged = mergeSettings({
      ollamaModel: 'mistral',
      anthropicModel: 'claude-sonnet-4-6',
    })
    expect(merged.ollamaModel).toBe('mistral')
    expect(merged.anthropicModel).toBe('claude-sonnet-4-6')
    expect(merged.ollamaUrl).toBe(DEFAULT_SETTINGS.ollamaUrl)
  })

  it('keeps an explicitly empty API key so the server env key is used', () => {
    expect(mergeSettings({ anthropicKey: '' }).anthropicKey).toBe('')
  })

  it('trims values and ignores empty strings for required fields', () => {
    expect(mergeSettings({ ollamaUrl: '   ' }).ollamaUrl).toBe(DEFAULT_SETTINGS.ollamaUrl)
    expect(mergeSettings({ ollamaModel: '  llama3.1  ' }).ollamaModel).toBe('llama3.1')
  })
})
