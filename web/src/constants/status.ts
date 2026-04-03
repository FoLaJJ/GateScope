import React from 'react'
import {
  ClockCircleOutlined,
  SyncOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  PauseCircleOutlined,
  StopOutlined,
} from '@ant-design/icons'
import type { TaskStatus } from '@/types'

export interface StatusConfig {
  color: string
  icon: React.ReactNode
  label: string
}

export const TASK_STATUS_CONFIG: Record<TaskStatus, StatusConfig> = {
  pending: { color: 'default', icon: React.createElement(ClockCircleOutlined), label: '待执行' },
  running: { color: 'processing', icon: React.createElement(SyncOutlined, { spin: true }), label: '执行中' },
  completed: { color: 'success', icon: React.createElement(CheckCircleOutlined), label: '已完成' },
  failed: { color: 'error', icon: React.createElement(CloseCircleOutlined), label: '失败' },
  paused: { color: 'warning', icon: React.createElement(PauseCircleOutlined), label: '已暂停' },
  cancelled: { color: 'default', icon: React.createElement(StopOutlined), label: '已取消' },
}

export const AUTH_MODE_LABELS: Record<string, string> = {
  none: '无认证',
  open: '开放',
  token: 'Token',
  token_auth: 'Token认证',
  device_auth: '设备认证',
  origin_restricted: '源限制',
}

export function authModeColor(mode?: string): string {
  if (!mode) return 'default'
  if (mode === 'none' || mode === 'open') return 'red'
  if (mode === 'device_auth' || mode === 'token_auth') return 'green'
  return 'orange'
}
