import { useMutation } from '@tanstack/react-query'
import { request } from './client'
import type { TargetImportResult } from '@/types'

export function useImportTargets() {
  return useMutation({
    mutationFn: (file: File) => {
      const form = new FormData()
      form.append('file', file)

      return request<TargetImportResult>('/import/targets', {
        method: 'POST',
        body: form,
      })
    },
  })
}
