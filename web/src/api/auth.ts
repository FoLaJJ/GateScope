import { request } from './client'
import type { LoginResponse, User } from '@/types'

export function login(username: string, password: string) {
  return request<LoginResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  })
}

export function getMe() {
  return request<{ user_id: string; username: string; role: string }>('/auth/me')
}

export type { User }
