import { describe, expect, it } from 'vitest'
import { buildQueryString, normalizeQueryParams, parseQueryParams } from '@/utils/query'

describe('query utils', () => {
  it('builds query string from non-empty params only', () => {
    expect(
      buildQueryString({
        page: 2,
        limit: 50,
        status: 'running',
        keyword: '',
      }),
    ).toBe('limit=50&page=2&status=running')
  })

  it('normalizes params by removing empty values', () => {
    expect(
      normalizeQueryParams({
        page: 1,
        limit: 20,
        status: '',
        severity: undefined,
        cve_id: 'CVE-2026-0001',
      }),
    ).toEqual({
      cve_id: 'CVE-2026-0001',
      limit: 20,
      page: 1,
    })
  })

  it('parses query params back into typed defaults', () => {
    const result = parseQueryParams(new URLSearchParams('page=3&limit=100&status=completed'), {
      page: 1,
      limit: 20,
      status: '',
    })

    expect(result).toEqual({
      page: 3,
      limit: 100,
      status: 'completed',
    })
  })
})
