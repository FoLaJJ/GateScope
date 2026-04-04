import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { INSTANCE_CHANGED_EVENT, WS_RECONNECTED_EVENT } from '@/runtime/instance'

export function useRuntimeSync() {
  const queryClient = useQueryClient()

  useEffect(() => {
    const handleInstanceChanged = () => {
      void queryClient.resetQueries()
    }

    const handleWSReconnected = () => {
      void queryClient.invalidateQueries()
    }

    window.addEventListener(INSTANCE_CHANGED_EVENT, handleInstanceChanged)
    window.addEventListener(WS_RECONNECTED_EVENT, handleWSReconnected)

    return () => {
      window.removeEventListener(INSTANCE_CHANGED_EVENT, handleInstanceChanged)
      window.removeEventListener(WS_RECONNECTED_EVENT, handleWSReconnected)
    }
  }, [queryClient])
}
