import React from 'react'
import { Tag } from 'antd'
import { RISK_TAG_COLORS, RISK_LABELS } from '@/constants'
import type { RiskLevel, Severity } from '@/types'

interface Props {
  level: RiskLevel | Severity | string
  style?: React.CSSProperties
}

export default function RiskTag({ level, style }: Props) {
  const color = RISK_TAG_COLORS[level as RiskLevel] || 'default'
  const label = RISK_LABELS[level as RiskLevel] || level
  return (
    <Tag color={color} style={style}>
      {label}
    </Tag>
  )
}
