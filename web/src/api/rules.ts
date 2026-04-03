import { useQuery } from '@tanstack/react-query'
import { request } from './client'
import type { RuleCatalogMetadata } from '@/types'

export const ruleKeys = {
  all: ['rules'] as const,
  catalog: () => [...ruleKeys.all, 'catalog'] as const,
}

export function useRuleCatalog() {
  return useQuery({
    queryKey: ruleKeys.catalog(),
    queryFn: () => request<RuleCatalogMetadata>('/rules/catalog'),
    staleTime: 60_000,
  })
}
