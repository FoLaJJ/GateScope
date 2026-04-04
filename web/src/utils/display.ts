export function displayUnknown(value: string | null | undefined, fallback = '未查明') {
  const normalized = String(value ?? '').trim()
  return normalized || fallback
}

export function displayUpperUnknown(value: string | null | undefined, fallback = '未查明') {
  const normalized = String(value ?? '').trim()
  return normalized ? normalized.toUpperCase() : fallback
}

export function toFiniteNumber(value: unknown): number | null {
  const numeric =
    typeof value === 'number'
      ? value
      : typeof value === 'string' && value.trim() !== ''
        ? Number(value)
        : Number.NaN
  return Number.isFinite(numeric) ? numeric : null
}

export function displayNumberUnknown(value: number | null | undefined, fallback = '未查明') {
  return typeof value === 'number' && !Number.isNaN(value) ? String(value) : fallback
}

export function displayCVSS(value: unknown, fallback = '-') {
  const numeric = toFiniteNumber(value)
  return numeric !== null ? numeric.toFixed(1) : fallback
}

export function displayPercent(value: unknown, fallback = '-') {
  const numeric = toFiniteNumber(value)
  return numeric !== null ? `${Math.round(numeric)}%` : fallback
}

export function displayProgressPercent(value: unknown, fallback = 0) {
  const numeric = toFiniteNumber(value)
  if (numeric === null) {
    return fallback
  }
  return Math.min(100, Math.max(0, Math.round(numeric)))
}

export function displayTimeUnknown(value: string | null | undefined, fallback = '未获取到') {
  const normalized = String(value ?? '').trim()
  if (!normalized) {
    return fallback
  }
  return new Date(normalized).toLocaleString('zh-CN')
}

export function displayJSONUnknown(value: unknown, fallback = '未获取到') {
  if (value == null) {
    return fallback
  }
  if (typeof value === 'string') {
    return value.trim() || fallback
  }
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return fallback
  }
}
