import { useQuery } from '@tanstack/react-query'
import { request } from './client'
import { buildQueryString, normalizeQueryParams } from '@/utils/query'
import type { Asset, Vulnerability, PaginatedResponse, AssetListParams } from '@/types'

export const assetKeys = {
  all: ['assets'] as const,
  lists: () => [...assetKeys.all, 'list'] as const,
  list: (params?: AssetListParams) => [...assetKeys.lists(), normalizeQueryParams(params)] as const,
  details: () => [...assetKeys.all, 'detail'] as const,
  detail: (id: string) => [...assetKeys.details(), id] as const,
  vulns: (id: string) => [...assetKeys.detail(id), 'vulns'] as const,
}

export function useAssetList(params?: AssetListParams) {
  return useQuery({
    queryKey: assetKeys.list(params),
    queryFn: () => {
      const query = buildQueryString(params)
      return request<PaginatedResponse<Asset>>(`/assets${query ? `?${query}` : ''}`)
    },
  })
}

export function useAsset(id: string) {
  return useQuery({
    queryKey: assetKeys.detail(id),
    queryFn: () => request<Asset>(`/assets/${id}`),
    enabled: !!id,
  })
}

export function useAssetVulns(id: string) {
  return useQuery({
    queryKey: assetKeys.vulns(id),
    queryFn: () => request<{ data: Vulnerability[] }>(`/assets/${id}/vulns`),
    enabled: !!id,
  })
}
