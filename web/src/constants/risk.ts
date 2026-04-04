import type { RiskLevel, Severity } from '@/types'

export const RISK_COLORS: Record<RiskLevel, string> = {
  critical: '#8f3125',
  high: '#c18b3b',
  medium: '#d6b164',
  low: '#6a845e',
  info: '#ad4d31',
}

export const RISK_TAG_COLORS: Record<RiskLevel, string> = {
  critical: 'red',
  high: 'red',
  medium: 'gold',
  low: 'green',
  info: 'green',
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
  if (score >= 9) return '#8f3125'
  if (score >= 7) return '#c18b3b'
  if (score >= 4) return '#d6b164'
  return '#6a845e'
}

export function confidenceColor(score: number): string {
  if (score >= 80) return '#6a845e'
  if (score >= 50) return '#c18b3b'
  return '#ad4d31'
}
