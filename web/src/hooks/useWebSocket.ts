import { useEffect, useRef, useCallback } from 'react'
import type { WSMessage } from '@/types'
import { notifyWSReconnected } from '@/runtime/instance'

type Listener = (msg: WSMessage) => void

interface WSState {
  ws: WebSocket | null
  listeners: Set<Listener>
  connectTimer: ReturnType<typeof setTimeout> | null
  reconnectTimer: ReturnType<typeof setTimeout> | null
  heartbeatTimer: ReturnType<typeof setInterval> | null
  reconnectDelay: number
  intentionalClose: boolean
  hasConnectedOnce: boolean
}

const MIN_RECONNECT = 1000
const MAX_RECONNECT = 30000
const HEARTBEAT_INTERVAL = 25000

const state: WSState = {
  ws: null,
  listeners: new Set(),
  connectTimer: null,
  reconnectTimer: null,
  heartbeatTimer: null,
  reconnectDelay: MIN_RECONNECT,
  intentionalClose: false,
  hasConnectedOnce: false,
}

function getWSUrl(): string | null {
  const token = localStorage.getItem('token')
  if (!token) {
    return null
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  const wsPath = '/api/v1/ws'
  const url = `${protocol}//${host}${wsPath}`
  return `${url}?token=${encodeURIComponent(token)}`
}

function startHeartbeat() {
  stopHeartbeat()
  state.heartbeatTimer = setInterval(() => {
    if (state.ws?.readyState === WebSocket.OPEN) {
      state.ws.send(JSON.stringify({ type: 'ping' }))
    }
  }, HEARTBEAT_INTERVAL)
}

function stopHeartbeat() {
  if (state.heartbeatTimer) {
    clearInterval(state.heartbeatTimer)
    state.heartbeatTimer = null
  }
}

function clearConnectTimer() {
  if (state.connectTimer) {
    clearTimeout(state.connectTimer)
    state.connectTimer = null
  }
}

function connect() {
  if (state.ws?.readyState === WebSocket.OPEN || state.ws?.readyState === WebSocket.CONNECTING) {
    return
  }

  const wsUrl = getWSUrl()
  if (!wsUrl) {
    return
  }

  const ws = new WebSocket(wsUrl)

  ws.onopen = () => {
    const isReconnect = state.hasConnectedOnce
    state.hasConnectedOnce = true
    state.reconnectDelay = MIN_RECONNECT
    startHeartbeat()
    if (isReconnect) {
      notifyWSReconnected()
    }
  }

  ws.onmessage = (event) => {
    try {
      const msg: WSMessage = JSON.parse(event.data)
      if (msg.type === 'pong') return
      state.listeners.forEach((fn) => {
        try {
          fn(msg)
        } catch (err) {
          console.error('[ws] listener error:', err)
        }
      })
    } catch (err) {
      console.warn('[ws] failed to parse message:', err)
    }
  }

  ws.onclose = () => {
    stopHeartbeat()
    state.ws = null
    if (!state.intentionalClose && state.listeners.size > 0) {
      state.reconnectTimer = setTimeout(() => {
        state.reconnectTimer = null
        state.reconnectDelay = Math.min(state.reconnectDelay * 2, MAX_RECONNECT)
        scheduleConnect()
      }, state.reconnectDelay)
    }
  }

  ws.onerror = () => {
    ws.close()
  }

  state.ws = ws
}

function scheduleConnect(delay = 0) {
  if (state.listeners.size === 0 || state.intentionalClose) {
    return
  }
  if (state.ws?.readyState === WebSocket.OPEN || state.ws?.readyState === WebSocket.CONNECTING || state.connectTimer) {
    return
  }

  state.connectTimer = setTimeout(() => {
    state.connectTimer = null
    connect()
  }, delay)
}

function disconnect() {
  state.intentionalClose = true
  clearConnectTimer()
  if (state.reconnectTimer) {
    clearTimeout(state.reconnectTimer)
    state.reconnectTimer = null
  }
  stopHeartbeat()
  state.ws?.close()
  state.ws = null
}

function subscribe(listener: Listener): () => void {
  state.listeners.add(listener)
  if (state.listeners.size === 1) {
    state.intentionalClose = false
    state.reconnectDelay = MIN_RECONNECT
    scheduleConnect()
  }
  return () => {
    state.listeners.delete(listener)
    if (state.listeners.size === 0) {
      disconnect()
    }
  }
}

export function useWebSocket(onMessage: Listener) {
  const savedCallback = useRef(onMessage)
  savedCallback.current = onMessage

  const stableListener = useCallback((msg: WSMessage) => {
    savedCallback.current(msg)
  }, [])

  useEffect(() => {
    return subscribe(stableListener)
  }, [stableListener])
}

export type { WSMessage }
