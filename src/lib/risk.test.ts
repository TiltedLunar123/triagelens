import { describe, expect, it } from 'vitest'
import type { Finding, Severity } from '../types'
import { SEVERITY_ORDER, maxSeverity, scoreRisk } from './risk'

const finding = (severity: Severity): Finding => ({
  id: severity,
  title: '',
  severity,
  description: '',
  evidence: [],
  techniques: [],
  recommendation: '',
})

describe('scoreRisk', () => {
  it('is 0 when there are no findings', () => {
    expect(scoreRisk([])).toBe(0)
  })

  it('weights a single critical above a single high', () => {
    expect(scoreRisk([finding('critical')])).toBeGreaterThan(scoreRisk([finding('high')]))
  })

  it('never exceeds 100', () => {
    const many = Array.from({ length: 12 }, () => finding('critical'))
    expect(scoreRisk(many)).toBeLessThanOrEqual(100)
  })

  it('keeps a single low finding in the low band', () => {
    expect(scoreRisk([finding('low')])).toBeLessThan(30)
  })
})

describe('maxSeverity', () => {
  it('returns info for an empty list', () => {
    expect(maxSeverity([])).toBe('info')
  })

  it('returns the highest severity present', () => {
    expect(maxSeverity([finding('low'), finding('critical'), finding('medium')])).toBe(
      'critical',
    )
  })
})

describe('SEVERITY_ORDER', () => {
  it('orders severities from low to high', () => {
    expect(SEVERITY_ORDER.indexOf('critical')).toBeGreaterThan(
      SEVERITY_ORDER.indexOf('info'),
    )
  })
})
