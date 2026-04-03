const API_BASE = '/api/v1'

let navigateToLogin: (() => void) | null = null

export function setAuthNavigator(fn: () => void) {
  navigateToLogin = fn
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

function extractErrorMessage(body: unknown, fallbackStatus: number) {
  if (!body || typeof body !== 'object') {
    return { code: 'UNKNOWN', message: `HTTP ${fallbackStatus}` }
  }

  const payload = body as {
    code?: string | number
    error?: string | { code?: string | number; message?: string; detail?: string }
    message?: string
    detail?: string
  }

  if (typeof payload.error === 'string') {
    return {
      code: String(payload.code ?? 'UNKNOWN'),
      message: payload.error || `HTTP ${fallbackStatus}`,
    }
  }

  if (payload.error && typeof payload.error === 'object') {
    const message = payload.error.detail
      ? `${payload.error.message ?? `HTTP ${fallbackStatus}`}: ${payload.error.detail}`
      : payload.error.message ?? `HTTP ${fallbackStatus}`

    return {
      code: String(payload.error.code ?? payload.code ?? 'UNKNOWN'),
      message,
    }
  }

  const message = payload.detail ? `${payload.message ?? `HTTP ${fallbackStatus}`}: ${payload.detail}` : payload.message
  return {
    code: String(payload.code ?? 'UNKNOWN'),
    message: message || `HTTP ${fallbackStatus}`,
  }
}

export function getDownloadFilename(contentDisposition: string | null, fallback: string) {
  if (!contentDisposition) return fallback

  const encodedMatch = contentDisposition.match(/filename\*\s*=\s*UTF-8''([^;]+)/i)
  if (encodedMatch?.[1]) {
    try {
      return decodeURIComponent(encodedMatch[1])
    } catch {
      return encodedMatch[1]
    }
  }

  const filenameMatch = contentDisposition.match(/filename\s*=\s*"([^"]+)"|filename\s*=\s*([^;]+)/i)
  return filenameMatch?.[1] || filenameMatch?.[2]?.trim() || fallback
}

export async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const token = localStorage.getItem('token')
  const headers = new Headers(options?.headers)

  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`)
  }

  if (options?.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  const resp = await fetch(`${API_BASE}${path}`, { ...options, headers })

  if (resp.status === 401) {
    localStorage.removeItem('token')
    localStorage.removeItem('username')
    navigateToLogin?.()
    throw new ApiError(401, 'UNAUTHORIZED', 'Unauthorized')
  }

  if (!resp.ok) {
    const body = await resp.json().catch(() => null)
    const { code, message } = extractErrorMessage(body, resp.status)
    throw new ApiError(resp.status, code, message)
  }

  if (resp.headers.get('content-type')?.includes('application/json')) {
    return resp.json()
  }
  return resp as unknown as T
}

export async function downloadFile(path: string, filename: string): Promise<void> {
  const token = localStorage.getItem('token')
  const resp = await fetch(`${API_BASE}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!resp.ok) throw new ApiError(resp.status, 'DOWNLOAD_FAILED', 'Download failed')
  const blob = await resp.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = getDownloadFilename(resp.headers.get('content-disposition'), filename)
  a.click()
  URL.revokeObjectURL(url)
}
