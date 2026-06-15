import { describe, expect, it } from 'vitest'
import { technique, techniques } from './attack'

describe('technique', () => {
  it('resolves a known top-level technique with its attack.mitre.org url', () => {
    const t = technique('T1059')
    expect(t.name).toBe('Command and Scripting Interpreter')
    expect(t.tactic).toBe('Execution')
    expect(t.url).toBe('https://attack.mitre.org/techniques/T1059/')
  })

  it('rewrites a sub-technique id into its url path', () => {
    const t = technique('T1059.001')
    expect(t.name).toBe('PowerShell')
    expect(t.url).toBe('https://attack.mitre.org/techniques/T1059/001/')
  })

  it('degrades gracefully for an unknown id', () => {
    const t = technique('T9999')
    expect(t).toEqual({
      id: 'T9999',
      name: 'T9999',
      tactic: 'Unknown',
      url: 'https://attack.mitre.org/techniques/T9999/',
    })
  })
})

describe('techniques', () => {
  it('resolves several ids in order', () => {
    const result = techniques('T1110', 'T1078')
    expect(result.map((t) => t.id)).toEqual(['T1110', 'T1078'])
    expect(result.map((t) => t.tactic)).toEqual([
      'Credential Access',
      'Defense Evasion',
    ])
  })

  it('returns an empty array when given no ids', () => {
    expect(techniques()).toEqual([])
  })
})
