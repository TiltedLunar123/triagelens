import { describe, expect, it } from 'vitest'
import { getProvider, PROVIDERS, type ProviderId } from './registry'

describe('provider registry', () => {
  it('registers three providers with the demo default listed first', () => {
    expect(PROVIDERS).toHaveLength(3)
    expect(PROVIDERS[0].id).toBe('demo')
  })

  it('gives every provider a unique id and a non-empty label', () => {
    const ids = PROVIDERS.map((p) => p.id)
    expect(new Set(ids).size).toBe(ids.length)
    expect(PROVIDERS.every((p) => p.label.length > 0)).toBe(true)
  })

  it('looks every registered provider up by its own id', () => {
    for (const provider of PROVIDERS) {
      expect(getProvider(provider.id)).toBe(provider)
    }
  })

  it('falls back to the demo provider for an unknown id', () => {
    expect(getProvider('mystery' as unknown as ProviderId).id).toBe('demo')
  })
})
