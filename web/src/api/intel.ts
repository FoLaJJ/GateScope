import { useMutation } from '@tanstack/react-query'
import { request } from './client'
import type {
  IntelResult,
  FOFASearchRequest,
  FOFASearchResponse,
  FOFAImportRequest,
  FOFAImportResponse,
} from '@/types'

export function useFOFASearch() {
  return useMutation({
    mutationFn: (payload: FOFASearchRequest) =>
      request<FOFASearchResponse<IntelResult>>('/intel/fofa/search', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
  })
}

export function useFOFAImport() {
  return useMutation({
    mutationFn: (payload: FOFAImportRequest) =>
      request<FOFAImportResponse>('/intel/fofa/import', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
  })
}
