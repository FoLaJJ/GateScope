import { useQuery } from '@tanstack/react-query'
import { request } from './client'
import type { PaginatedResponse, RuleCatalogEntry, RuleCatalogMetadata } from '@/types'

export const ruleKeys = {
  all: ['rules'] as const,
  catalog: () => [...ruleKeys.all, 'catalog'] as const,
  entries: () => [...ruleKeys.all, 'entries'] as const,
}

export function useRuleCatalog() {
  return useQuery({
    queryKey: ruleKeys.catalog(),
    queryFn: () => request<RuleCatalogMetadata>('/rules/catalog'),
    staleTime: 60_000,
  })
}

export function useRuleCatalogEntries() {
  return useQuery({
    queryKey: ruleKeys.entries(),
    queryFn: () => request<PaginatedResponse<RuleCatalogEntry>>('/rules/catalog/entries'),
    staleTime: 60_000,
  })
}
