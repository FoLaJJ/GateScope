import { describe, it, expect, beforeEach } from 'vitest'
import { useAuthStore } from '@/store/auth'

beforeEach(() => {
  localStorage.clear()
  useAuthStore.setState({ token: null, username: null })
})

describe('auth store', () => {
  it('setAuth stores token and username', () => {
    const { setAuth } = useAuthStore.getState()
    setAuth('test-token', 'admin')

    const state = useAuthStore.getState()
    expect(state.token).toBe('test-token')
    expect(state.username).toBe('admin')
    expect(localStorage.getItem('token')).toBe('test-token')
    expect(localStorage.getItem('username')).toBe('admin')
  })

  it('logout clears token and username', () => {
    const { setAuth, logout } = useAuthStore.getState()
    setAuth('test-token', 'admin')
    logout()

    const state = useAuthStore.getState()
    expect(state.token).toBeNull()
    expect(state.username).toBeNull()
    expect(localStorage.getItem('token')).toBeNull()
  })
})
