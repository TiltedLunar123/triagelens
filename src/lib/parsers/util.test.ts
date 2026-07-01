import { describe, expect, it } from 'vitest'
import { asString, baseName, pick } from './util'

describe('baseName', () => {
  it('strips a Windows path down to the file name', () => {
    expect(baseName('C:\\Windows\\System32\\cmd.exe')).toBe('cmd.exe')
  })

  it('strips a Unix path down to the file name', () => {
    expect(baseName('/usr/bin/bash')).toBe('bash')
  })

  it('returns a bare file name unchanged', () => {
    expect(baseName('powershell.exe')).toBe('powershell.exe')
  })

  it('returns undefined when no path is given', () => {
    expect(baseName(undefined)).toBeUndefined()
  })

  it('keeps the original value when the path ends in a separator', () => {
    // split leaves a trailing empty segment, so the helper falls back to the input
    expect(baseName('C:\\Windows\\')).toBe('C:\\Windows\\')
  })
})

describe('asString', () => {
  it('returns undefined for null and undefined', () => {
    expect(asString(null)).toBeUndefined()
    expect(asString(undefined)).toBeUndefined()
  })

  it('coerces a number to its string form', () => {
    expect(asString(42)).toBe('42')
  })

  it('preserves the zero value as a string', () => {
    expect(asString(0)).toBe('0')
  })

  it('trims surrounding whitespace', () => {
    expect(asString('  powershell.exe  ')).toBe('powershell.exe')
  })

  it('returns undefined for an empty or whitespace-only string', () => {
    expect(asString('')).toBeUndefined()
    expect(asString('   ')).toBeUndefined()
  })
})

describe('pick', () => {
  it('returns the value of the first present key', () => {
    expect(pick({ a: 1, b: 2 }, 'a', 'b')).toBe(1)
  })

  it('skips keys whose value is null or undefined', () => {
    expect(pick({ a: null, b: 2 }, 'a', 'b')).toBe(2)
    expect(pick({ a: undefined, b: 3 }, 'a', 'b')).toBe(3)
  })

  it('treats a zero value as present', () => {
    expect(pick({ a: 0, b: 9 }, 'a', 'b')).toBe(0)
  })

  it('honours the order the keys are passed in', () => {
    expect(pick({ a: 1, b: 2 }, 'b', 'a')).toBe(2)
  })

  it('returns undefined when no key matches', () => {
    expect(pick({ a: 1 }, 'x', 'y')).toBeUndefined()
  })
})
