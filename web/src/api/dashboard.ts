import { useQuery } from '@tanstack/react-query'
import { request } from './client'
import type { DashboardStats } from '@/types'

export const dashboardKeys = {
  all: ['dashboard'] as const,
  stats: () => [...dashboardKeys.all, 'stats'] as const,
}

export function useDashboardStats() {
  return useQuery({
    queryKey: dashboardKeys.stats(),
    queryFn: () => request<DashboardStats>('/dashboard/stats'),
    refetchInterval: 30_000,
  })
}
