import { useQuery } from '@tanstack/react-query'
import { request } from './client'
import { buildQueryString, normalizeQueryParams } from '@/utils/query'
import type { Vulnerability, PaginatedResponse, VulnListParams } from '@/types'

export const vulnKeys = {
  all: ['vulns'] as const,
  lists: () => [...vulnKeys.all, 'list'] as const,
  list: (params?: VulnListParams) => [...vulnKeys.lists(), normalizeQueryParams(params)] as const,
  details: () => [...vulnKeys.all, 'detail'] as const,
  detail: (id: string) => [...vulnKeys.details(), id] as const,
}

export function useVulnList(params?: VulnListParams) {
  return useQuery({
    queryKey: vulnKeys.list(params),
    queryFn: () => {
      const query = buildQueryString(params)
      return request<PaginatedResponse<Vulnerability>>(`/vulns${query ? `?${query}` : ''}`)
    },
  })
}

export function useVuln(id: string) {
  return useQuery({
    queryKey: vulnKeys.detail(id),
    queryFn: () => request<Vulnerability>(`/vulns/${id}`),
    enabled: !!id,
  })
}
