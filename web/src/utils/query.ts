export type QueryState = Record<string, string | number>
type QueryParamValue = string | number | null | undefined

export function normalizeQueryParams<T extends object>(params?: T) {
  if (!params) return {} as Partial<T>

  const entries = Object.entries(params as Record<string, QueryParamValue>)
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .sort(([left], [right]) => left.localeCompare(right))

  return Object.fromEntries(entries) as Partial<T>
}

export function buildQueryString<T extends object>(params?: T) {
  const normalized = normalizeQueryParams(params)
  return new URLSearchParams(
    Object.entries(normalized as Record<string, QueryParamValue>).map(([key, value]) => [key, String(value)]),
  ).toString()
}

export function parseQueryParams<T extends QueryState>(search: URLSearchParams, defaults: T): T {
  const next = { ...defaults }

  for (const key of Object.keys(defaults) as Array<keyof T>) {
    const value = search.get(String(key))
    if (value === null || value === '') {
      continue
    }

    if (typeof defaults[key] === 'number') {
      const parsed = Number(value)
      if (!Number.isNaN(parsed)) {
        next[key] = parsed as T[keyof T]
      }
      continue
    }

    next[key] = value as T[keyof T]
  }

  return next
}
