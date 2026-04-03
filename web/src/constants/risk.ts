import type { RiskLevel, Severity } from '@/types'

export const RISK_COLORS: Record<RiskLevel, string> = {
  critical: '#f5222d',
  high: '#fa8c16',
  medium: '#fadb14',
  low: '#52c41a',
  info: '#1677ff',
}

export const RISK_TAG_COLORS: Record<RiskLevel, string> = {
  critical: 'red',
  high: 'orange',
  medium: 'gold',
  low: 'green',
  info: 'blue',
}

export const RISK_LABELS: Record<RiskLevel, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
}

export const SEVERITY_LABELS: Record<Severity, string> = RISK_LABELS
export const SEVERITY_COLORS: Record<Severity, string> = RISK_COLORS
export const SEVERITY_TAG_COLORS: Record<Severity, string> = RISK_TAG_COLORS

export const RISK_LEVELS: RiskLevel[] = ['critical', 'high', 'medium', 'low', 'info']

export function getRiskOptions() {
  return RISK_LEVELS.map((k) => ({ label: RISK_LABELS[k], value: k }))
}

export function cvssColor(score: number): string {
  if (score >= 9) return '#f5222d'
  if (score >= 7) return '#fa8c16'
  if (score >= 4) return '#faad14'
  return '#52c41a'
}

export function confidenceColor(score: number): string {
  if (score >= 80) return '#52c41a'
  if (score >= 50) return '#faad14'
  return '#ff4d4f'
}
