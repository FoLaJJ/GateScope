import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { message } from 'antd'
import { describe, expect, it, beforeEach, vi } from 'vitest'
import Alerts from './Alerts'
import { useAlertHistory, useAlertRules, useTestWebhook, useUpdateAlertRules } from '@/api/alert'
import { makeAlertRecord, makeAlertRule } from '@/test-utils/fixtures'
import { renderWithProviders } from '@/test-utils/render'

vi.mock('@/api/alert', () => ({
  useAlertRules: vi.fn(),
  useUpdateAlertRules: vi.fn(),
  useAlertHistory: vi.fn(),
  useTestWebhook: vi.fn(),
}))

function createMutationMock() {
  return {
    mutateAsync: vi.fn(),
    isPending: false,
  }
}

describe('Alerts page', () => {
  const updateRulesMutation = createMutationMock()
  const testWebhookMutation = createMutationMock()

  beforeEach(() => {
    vi.mocked(useAlertRules).mockReturnValue({
      data: [makeAlertRule()],
      isLoading: false,
      refetch: vi.fn(),
    } as never)
    vi.mocked(useAlertHistory).mockReturnValue({
      data: [makeAlertRecord({ rule_name: 'Webhook告警' })],
      isLoading: false,
    } as never)
    vi.mocked(useUpdateAlertRules).mockReturnValue(updateRulesMutation as never)
    vi.mocked(useTestWebhook).mockReturnValue(testWebhookMutation as never)
    vi.spyOn(message, 'success').mockImplementation(() => ({}) as never)
    vi.spyOn(message, 'warning').mockImplementation(() => ({}) as never)
    vi.spyOn(message, 'error').mockImplementation(() => ({}) as never)
  })

  it('renders rules tab and history tab content', async () => {
    const user = userEvent.setup()

    renderWithProviders(<Alerts />, '/alerts')

    expect(screen.getByText('保存会整体覆盖当前规则列表，请确认后再提交。')).toBeInTheDocument()
    expect(screen.getByDisplayValue('严重漏洞')).toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: '告警历史' }))

    expect(await screen.findByText('Webhook告警')).toBeInTheDocument()
    expect(screen.getByText('已发送')).toBeInTheDocument()
  })

  it('validates empty rule name before saving', async () => {
    const user = userEvent.setup()

    renderWithProviders(<Alerts />, '/alerts')

    await user.clear(screen.getByDisplayValue('严重漏洞'))
    await user.click(screen.getByRole('button', { name: /保存规则/ }))

    expect(message.error).toHaveBeenCalledWith('规则名称不能为空')
    expect(updateRulesMutation.mutateAsync).not.toHaveBeenCalled()
  })

  it('shows helpful warning when webhook url is not configured', async () => {
    const user = userEvent.setup()
    testWebhookMutation.mutateAsync.mockRejectedValue(new Error('webhook URL not configured'))

    renderWithProviders(<Alerts />, '/alerts')

    await user.click(screen.getByRole('button', { name: /测试 Webhook/ }))

    await waitFor(() => {
      expect(message.warning).toHaveBeenCalledWith(
        '当前未配置 Webhook URL。请先在 _data/config.yaml 中设置 alert.webhook_url，并按需开启 alert.enabled。',
      )
    })
  })
})
