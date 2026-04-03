import { Tag } from 'antd'
import { AUTH_MODE_LABELS, authModeColor } from '@/constants'

interface Props {
  mode?: string
}

export default function AuthTag({ mode }: Props) {
  const color = authModeColor(mode)
  const label = AUTH_MODE_LABELS[mode ?? ''] || mode || '未知'
  return <Tag color={color}>{label}</Tag>
}
