import { describe, it, expect } from 'vitest'
import {
  RISK_COLORS,
  RISK_LABELS,
  RISK_TAG_COLORS,
  RISK_LEVELS,
  getRiskOptions,
  cvssColor,
  confidenceColor,
} from '@/constants/risk'
import { TASK_STATUS_CONFIG, AUTH_MODE_LABELS, authModeColor } from '@/constants/status'
import { CHECK_TYPE_LABELS, getCheckTypeOptions } from '@/constants/check'

describe('risk constants', () => {
  it('should have all risk levels defined', () => {
    for (const level of RISK_LEVELS) {
      expect(RISK_COLORS[level]).toBeDefined()
      expect(RISK_LABELS[level]).toBeDefined()
      expect(RISK_TAG_COLORS[level]).toBeDefined()
    }
  })

  it('getRiskOptions returns all levels', () => {
    const options = getRiskOptions()
    expect(options).toHaveLength(5)
    expect(options[0]).toEqual({ label: '严重', value: 'critical' })
  })

  it('risk tag colors use red/yellow/green tiers', () => {
    expect(RISK_TAG_COLORS.critical).toBe('red')
    expect(RISK_TAG_COLORS.high).toBe('red')
    expect(RISK_TAG_COLORS.medium).toBe('gold')
    expect(RISK_TAG_COLORS.low).toBe('green')
    expect(RISK_TAG_COLORS.info).toBe('green')
  })

  it('cvssColor returns correct colors', () => {
    expect(cvssColor(9.5)).toBe('#8f3125')
    expect(cvssColor(7.5)).toBe('#c18b3b')
    expect(cvssColor(5.0)).toBe('#d6b164')
    expect(cvssColor(2.0)).toBe('#6a845e')
  })

  it('confidenceColor returns correct colors', () => {
    expect(confidenceColor(90)).toBe('#6a845e')
    expect(confidenceColor(60)).toBe('#c18b3b')
    expect(confidenceColor(30)).toBe('#ad4d31')
  })
})

describe('status constants', () => {
  it('should have all task statuses defined', () => {
    for (const status of ['pending', 'running', 'completed', 'failed', 'paused']) {
      expect(TASK_STATUS_CONFIG[status as keyof typeof TASK_STATUS_CONFIG]).toBeDefined()
      expect(TASK_STATUS_CONFIG[status as keyof typeof TASK_STATUS_CONFIG].label).toBeDefined()
    }
  })

  it('authModeColor returns correct colors', () => {
    expect(authModeColor('none')).toBe('red')
    expect(authModeColor('open')).toBe('red')
    expect(authModeColor('device_auth')).toBe('green')
    expect(authModeColor('token_auth')).toBe('green')
    expect(authModeColor('unknown')).toBe('orange')
    expect(authModeColor(undefined)).toBe('default')
  })

  it('AUTH_MODE_LABELS has expected entries', () => {
    expect(AUTH_MODE_LABELS['none']).toBe('无认证')
    expect(AUTH_MODE_LABELS['token_auth']).toBe('Token认证')
  })
})

describe('check constants', () => {
  it('should have check type labels', () => {
    expect(CHECK_TYPE_LABELS['cve_match']).toBe('版本匹配')
    expect(CHECK_TYPE_LABELS['poc_verify']).toBe('PoC实证')
  })

  it('getCheckTypeOptions returns options', () => {
    const options = getCheckTypeOptions()
    expect(options.length).toBeGreaterThan(0)
    expect(options[0]).toHaveProperty('label')
    expect(options[0]).toHaveProperty('value')
  })
})
