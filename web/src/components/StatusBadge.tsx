import { Badge, type BadgeProps } from 'antd'
import { TASK_STATUS_CONFIG } from '@/constants'
import type { TaskStatus } from '@/types'

interface Props {
  status: TaskStatus | string
  showIcon?: boolean
}

export default function StatusBadge({ status, showIcon = true }: Props) {
  const config = TASK_STATUS_CONFIG[status as TaskStatus] ?? TASK_STATUS_CONFIG.pending
  return (
    <Badge
      status={config.color as BadgeProps['status']}
      text={
        <span>
          {showIcon && config.icon} {config.label}
        </span>
      }
    />
  )
}
