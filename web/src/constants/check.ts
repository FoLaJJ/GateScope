import type { CheckType } from '@/types'

export const CHECK_TYPE_LABELS: Record<CheckType | string, string> = {
  cve_match: '版本匹配',
  auth_check: '认证检查',
  skills_check: '暴露面检查',
  poc_verify: 'PoC实证',
  ws_hijack: 'WS劫持',
  path_traversal: '路径穿越',
  ssrf: 'SSRF',
}

export function getCheckTypeOptions() {
  return Object.entries(CHECK_TYPE_LABELS).map(([k, v]) => ({ label: v, value: k }))
}
