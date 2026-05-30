/** Strip a Windows or Unix path down to its file name. */
export function baseName(path?: string): string | undefined {
  if (!path) return undefined
  const parts = path.split(/[\\/]/)
  return parts[parts.length - 1] || path
}

/** Coerce an unknown value to a trimmed string, or undefined when empty. */
export function asString(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined
  const s = String(value).trim()
  return s.length > 0 ? s : undefined
}

/** First defined value among the provided record keys. */
export function pick(record: Record<string, any>, ...keys: string[]): unknown {
  for (const key of keys) {
    if (record[key] !== undefined && record[key] !== null) return record[key]
  }
  return undefined
}
