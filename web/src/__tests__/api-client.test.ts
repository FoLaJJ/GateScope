import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { request, downloadFile, ApiError, getDownloadFilename, setAuthNavigator } from '@/api/client'

beforeEach(() => {
  localStorage.setItem('token', 'test-token')
})

afterEach(() => {
  vi.restoreAllMocks()
  localStorage.clear()
})

describe('API client', () => {
  it('sends authorization header when token exists', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve({ data: 'test' }),
    })

    await request('/test')

    const options = vi.mocked(globalThis.fetch).mock.calls[0]?.[1]
    expect(options?.headers).toBeInstanceOf(Headers)
    expect((options?.headers as Headers).get('Authorization')).toBe('Bearer test-token')
  })

  it('throws ApiError on nested non-OK response', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: () =>
        Promise.resolve({
          error: {
            code: 500,
            message: 'create task failed',
            detail: 'database unavailable',
          },
        }),
    })

    await expect(request('/test')).rejects.toMatchObject({
      name: 'ApiError',
      code: '500',
      message: 'create task failed: database unavailable',
    } satisfies Partial<ApiError>)
  })

  it('calls auth navigator on 401', async () => {
    const navigator = vi.fn()
    setAuthNavigator(navigator)

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: () => Promise.resolve({ error: 'Unauthorized' }),
    })

    await expect(request('/test')).rejects.toThrow(ApiError)
    expect(navigator).toHaveBeenCalled()
  })

  it('does not force JSON content type for FormData uploads', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve({ message: 'ok' }),
    })

    const form = new FormData()
    form.append('file', new Blob(['targets']), 'targets.txt')

    await request('/upload', {
      method: 'POST',
      body: form,
      headers: { 'X-Trace': 'upload-test' },
    })

    const options = vi.mocked(globalThis.fetch).mock.calls[0]?.[1]
    expect((options?.headers as Headers).get('Content-Type')).toBeNull()
    expect((options?.headers as Headers).get('X-Trace')).toBe('upload-test')
  })

  it('prefers filename from response header when downloading files', async () => {
    const click = vi.fn()
    const anchor = {
      click,
      href: '',
      download: '',
    } as unknown as HTMLAnchorElement

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-disposition': 'attachment; filename="server.xlsx"' }),
      blob: () => Promise.resolve(new Blob(['report'])),
    })

    vi.spyOn(document, 'createElement').mockReturnValue(anchor)
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:report')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})

    await downloadFile('/reports/demo', 'fallback.xlsx')

    expect(anchor.download).toBe('server.xlsx')
    expect(click).toHaveBeenCalled()
  })

  it('falls back to provided filename when response header is missing', () => {
    expect(getDownloadFilename(null, 'fallback.xlsx')).toBe('fallback.xlsx')
  })
})
