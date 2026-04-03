import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { request } from './client'
import { buildQueryString, normalizeQueryParams } from '@/utils/query'
import type { Task, TaskEvent, TaskTargetStatus, CreateTaskRequest, PaginatedResponse, TaskListParams } from '@/types'

export const taskKeys = {
  all: ['tasks'] as const,
  lists: () => [...taskKeys.all, 'list'] as const,
  list: (params?: TaskListParams) => [...taskKeys.lists(), normalizeQueryParams(params)] as const,
  details: () => [...taskKeys.all, 'detail'] as const,
  detail: (id: string) => [...taskKeys.details(), id] as const,
  targets: (id: string) => [...taskKeys.detail(id), 'targets'] as const,
  events: (id: string, limit = 200) => [...taskKeys.all, 'events', id, limit] as const,
}

export function useTaskList(params?: TaskListParams) {
  return useQuery({
    queryKey: taskKeys.list(params),
    queryFn: () => {
      const query = buildQueryString(params)
      return request<PaginatedResponse<Task>>(`/tasks${query ? `?${query}` : ''}`)
    },
    refetchInterval: 10_000,
  })
}

export function useTask(id: string) {
  return useQuery({
    queryKey: taskKeys.detail(id),
    queryFn: () => request<Task>(`/tasks/${id}`),
    enabled: !!id,
  })
}

export function useTaskEvents(id: string, limit = 200) {
  return useQuery({
    queryKey: taskKeys.events(id, limit),
    queryFn: () => request<{ data: TaskEvent[]; total: number }>(`/tasks/${id}/events?limit=${limit}`),
    enabled: !!id,
  })
}

export function useTaskTargets(id: string) {
  return useQuery({
    queryKey: taskKeys.targets(id),
    queryFn: () => request<{ data: TaskTargetStatus[]; total: number }>(`/tasks/${id}/targets`),
    enabled: !!id,
  })
}

export function useCreateTask() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: CreateTaskRequest) => request<Task>('/tasks', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: taskKeys.lists() })
    },
  })
}

export function useStartTask() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => request<Task>(`/tasks/${id}/start`, { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: taskKeys.all })
    },
  })
}

export function useStopTask() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => request<Task>(`/tasks/${id}/stop`, { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: taskKeys.all })
    },
  })
}

export function useDeleteTask() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => request<void>(`/tasks/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: taskKeys.lists() })
    },
  })
}
