import { useEffect, useRef, useCallback } from 'react'
import type { WSMessage } from '@/types'

type Listener = (msg: WSMessage) => void

interface WSState {
  ws: WebSocket | null
  listeners: Set<Listener>
  reconnectTimer: ReturnType<typeof setTimeout> | null
  heartbeatTimer: ReturnType<typeof setInterval> | null
  reconnectDelay: number
  intentionalClose: boolean
}

const MIN_RECONNECT = 1000
const MAX_RECONNECT = 30000
const HEARTBEAT_INTERVAL = 25000

const state: WSState = {
  ws: null,
  listeners: new Set(),
  reconnectTimer: null,
  heartbeatTimer: null,
  reconnectDelay: MIN_RECONNECT,
  intentionalClose: false,
}

function getWSUrl(): string {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  const wsPath = '/api/v1/ws'
  const token = localStorage.getItem('token')
  const url = `${protocol}//${host}${wsPath}`
  return token ? `${url}?token=${encodeURIComponent(token)}` : url
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

function connect() {
  if (state.ws?.readyState === WebSocket.OPEN || state.ws?.readyState === WebSocket.CONNECTING) {
    return
  }

  const ws = new WebSocket(getWSUrl())

  ws.onopen = () => {
    state.reconnectDelay = MIN_RECONNECT
    startHeartbeat()
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
        state.reconnectDelay = Math.min(state.reconnectDelay * 2, MAX_RECONNECT)
        connect()
      }, state.reconnectDelay)
    }
  }

  ws.onerror = () => {
    ws.close()
  }

  state.ws = ws
}

function disconnect() {
  state.intentionalClose = true
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
    connect()
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
