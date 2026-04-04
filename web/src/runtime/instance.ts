export const API_INSTANCE_HEADER = 'X-GateScope-Instance'
export const INSTANCE_CHANGED_EVENT = 'gatescope:instance-changed'
export const WS_RECONNECTED_EVENT = 'gatescope:ws-reconnected'

const STORAGE_KEY = 'gatescope.instance'

let currentInstance = readStoredInstance()

function readStoredInstance() {
  if (typeof window === 'undefined') {
    return null
  }
  try {
    return window.sessionStorage.getItem(STORAGE_KEY)
  } catch {
    return null
  }
}

function writeStoredInstance(instance: string) {
  if (typeof window === 'undefined') {
    return
  }
  try {
    window.sessionStorage.setItem(STORAGE_KEY, instance)
  } catch {
    // Ignore storage failures; in-memory tracking is enough for runtime invalidation.
  }
}

export function processRuntimeInstance(instance: string | null) {
  const next = instance?.trim()
  if (!next) {
    return
  }

  const previous = currentInstance
  currentInstance = next
  writeStoredInstance(next)

  if (previous && previous !== next) {
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent(INSTANCE_CHANGED_EVENT, { detail: { previous, current: next } }))
    }
  }
}

export function notifyWSReconnected() {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new Event(WS_RECONNECTED_EVENT))
  }
}
