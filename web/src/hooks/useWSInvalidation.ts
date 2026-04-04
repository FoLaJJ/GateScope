import { useCallback } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useWebSocket } from './useWebSocket'
import { taskKeys } from '@/api/tasks'
import { assetKeys } from '@/api/assets'
import { vulnKeys } from '@/api/vulns'
import { dashboardKeys } from '@/api/dashboard'
import type { WSMessage } from '@/types'

const EVENT_TO_KEYS: Record<string, readonly (readonly string[])[]> = {
  'task.progress': [taskKeys.all],
  'task.completed': [taskKeys.all, dashboardKeys.all],
  'agent.identified': [assetKeys.all, dashboardKeys.all],
  'vuln.detected': [vulnKeys.all, dashboardKeys.all],
  'asset.changed': [assetKeys.all, dashboardKeys.all],
}

export function useWSInvalidation(extraHandler?: (msg: WSMessage) => void) {
  const qc = useQueryClient()

  const onMessage = useCallback(
    (msg: WSMessage) => {
      const keys = EVENT_TO_KEYS[msg.type]
      if (keys) {
        keys.forEach((key) => qc.invalidateQueries({ queryKey: [...key] }))
      }
      extraHandler?.(msg)
    },
    [qc, extraHandler],
  )

  useWebSocket(onMessage)
}
