import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import TaskDetail from './TaskDetail'
import { useAssetList } from '@/api/assets'
import { exportExcel } from '@/api/reports'
import { useRuleCatalog } from '@/api/rules'
import { useTask, useTaskEvents, useTaskTargets } from '@/api/tasks'
import { useVulnList } from '@/api/vulns'
import { makeAsset, makeTask, makeVulnerability } from '@/test-utils/fixtures'
import { renderWithProviders } from '@/test-utils/render'

vi.mock('@/api/tasks', () => ({
  useTask: vi.fn(),
  useTaskEvents: vi.fn(),
  useTaskTargets: vi.fn(),
}))

vi.mock('@/api/assets', () => ({
  useAssetList: vi.fn(),
}))

vi.mock('@/api/vulns', () => ({
  useVulnList: vi.fn(),
}))

vi.mock('@/api/reports', () => ({
  exportExcel: vi.fn(),
}))

vi.mock('@/api/rules', () => ({
  useRuleCatalog: vi.fn(),
}))

describe('TaskDetail page', () => {
  it('renders details and exports report for completed tasks', async () => {
    const user = userEvent.setup()
    vi.mocked(useTask).mockReturnValue({
      data: makeTask({ id: 'task-1', name: '扫描任务A', status: 'completed' }),
      isLoading: false,
      refetch: vi.fn(),
    } as never)
    vi.mocked(useAssetList).mockReturnValue({
      data: { data: [makeAsset()], total: 1 },
    } as never)
    vi.mocked(useTaskTargets).mockReturnValue({
      data: {
        data: [
          {
            target: '1.1.1.1',
            status: 'identified',
            status_text: '已识别 Agent',
            summary: '已识别为 openclaw 资产',
            asset_id: 'asset-1',
            ip: '1.1.1.1',
            port: 18789,
            agent_type: 'openclaw',
            version: '1.0.0',
            auth_mode: 'token',
            risk_level: 'high',
            confidence: 92,
            vuln_count: 1,
          },
        ],
        total: 1,
      },
    } as never)
    vi.mocked(useTaskEvents).mockReturnValue({
      data: { data: [], total: 0 },
    } as never)
    vi.mocked(useVulnList).mockReturnValue({
      data: {
        data: [makeVulnerability({ asset_ip: '1.1.1.1', asset_port: 18789, agent_type: 'openclaw' })],
        total: 1,
      },
    } as never)
    vi.mocked(useRuleCatalog).mockReturnValue({
      data: {
        updated_at: '2026-04-03',
        source_cutoff: '2026-04-03',
        rule_count: 12,
        cve_count: 10,
        cnnvd_count: 2,
        ghsa_count: 3,
        poc_count: 4,
        consistent: true,
        issues: [],
      },
    } as never)

    renderWithProviders(
      <Routes>
        <Route path="/tasks/:id" element={<TaskDetail />} />
      </Routes>,
      '/tasks/task-1',
    )

    expect(screen.getByText('扫描任务A')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /导出报告/ })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /导出报告/ }))
    expect(exportExcel).toHaveBeenCalledWith('task-1')
  })

  it('shows error message and hides report button for failed tasks', () => {
    vi.mocked(useTask).mockReturnValue({
      data: makeTask({ status: 'failed', error_message: 'network timeout' }),
      isLoading: false,
      refetch: vi.fn(),
    } as never)
    vi.mocked(useAssetList).mockReturnValue({
      data: { data: [], total: 0 },
    } as never)
    vi.mocked(useTaskTargets).mockReturnValue({
      data: {
        data: [
          {
            target: '1.1.1.1',
            status: 'scanned_no_agent',
            status_text: '未识别 Agent',
            summary: '目标已扫描，但未识别到受支持的 Agent。',
          },
        ],
        total: 1,
      },
    } as never)
    vi.mocked(useTaskEvents).mockReturnValue({
      data: { data: [], total: 0 },
    } as never)
    vi.mocked(useVulnList).mockReturnValue({
      data: { data: [], total: 0 },
    } as never)
    vi.mocked(useRuleCatalog).mockReturnValue({
      data: {
        updated_at: '2026-04-03',
        source_cutoff: '2026-04-03',
        rule_count: 12,
        cve_count: 10,
        cnnvd_count: 2,
        ghsa_count: 3,
        poc_count: 4,
        consistent: true,
        issues: [],
      },
    } as never)

    renderWithProviders(
      <Routes>
        <Route path="/tasks/:id" element={<TaskDetail />} />
      </Routes>,
      '/tasks/task-1',
    )

    expect(screen.getByText('错误: network timeout')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /导出报告/ })).not.toBeInTheDocument()
    expect(screen.getByText('未识别 Agent')).toBeInTheDocument()
  })
})
