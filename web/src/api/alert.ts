import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { request } from './client'
import type { AlertRule, AlertRecord, MessageResponse } from '@/types'

export const alertKeys = {
  all: ['alerts'] as const,
  rules: () => [...alertKeys.all, 'rules'] as const,
  history: (limit: number) => [...alertKeys.all, 'history', limit] as const,
}

export function useAlertRules() {
  return useQuery({
    queryKey: alertKeys.rules(),
    queryFn: async () => {
      const response = await request<{ data: AlertRule[] }>('/alert/rules')
      return response.data
    },
  })
}

export function useUpdateAlertRules() {
  const qc = useQueryClient()

  return useMutation({
    mutationFn: (rules: AlertRule[]) =>
      request<MessageResponse>('/alert/rules', {
        method: 'PUT',
        body: JSON.stringify({ rules }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: alertKeys.rules() })
    },
  })
}

export function useAlertHistory(limit = 100) {
  return useQuery({
    queryKey: alertKeys.history(limit),
    queryFn: async () => {
      const response = await request<{ data: AlertRecord[] }>(`/alert/history?limit=${limit}`)
      return response.data
    },
  })
}

export function useTestWebhook() {
  return useMutation({
    mutationFn: () => request<MessageResponse>('/alert/test', { method: 'POST' }),
  })
}
