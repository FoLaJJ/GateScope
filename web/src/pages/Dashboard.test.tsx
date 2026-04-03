import { screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import Dashboard from './Dashboard'
import { useDashboardStats } from '@/api/dashboard'
import { useTaskList } from '@/api/tasks'
import { useVulnList } from '@/api/vulns'
import { makeDashboardStats, makeTask, makeVulnerability } from '@/test-utils/fixtures'
import { renderWithProviders } from '@/test-utils/render'

vi.mock('echarts-for-react', () => ({
  default: () => <div data-testid="chart-placeholder" />,
}))

vi.mock('@/api/dashboard', () => ({
  useDashboardStats: vi.fn(),
}))

vi.mock('@/api/tasks', () => ({
  useTaskList: vi.fn(),
}))

vi.mock('@/api/vulns', () => ({
  useVulnList: vi.fn(),
}))

describe('Dashboard page', () => {
  it('renders stats, charts and recent lists', () => {
    vi.mocked(useDashboardStats).mockReturnValue({
      data: makeDashboardStats(),
      isLoading: false,
    } as never)
    vi.mocked(useTaskList).mockReturnValue({
      data: {
        data: [makeTask({ name: '最近任务A', found_agents: 2, found_vulns: 1 })],
        total: 1,
      },
    } as never)
    vi.mocked(useVulnList).mockReturnValue({
      data: {
        data: [makeVulnerability({ title: '远程代码执行', cve_id: 'CVE-2026-1000' })],
        total: 1,
      },
    } as never)

    renderWithProviders(<Dashboard />)

    expect(screen.getByRole('heading', { name: '安全态势总览' })).toBeInTheDocument()
    expect(screen.getByText('扫描任务')).toBeInTheDocument()
    expect(screen.getByText('发现Agent')).toBeInTheDocument()
    expect(screen.getByText('最近任务')).toBeInTheDocument()
    expect(screen.getByText('最近任务A')).toBeInTheDocument()
    expect(screen.getByText('远程代码执行')).toBeInTheDocument()
    expect(screen.getAllByTestId('chart-placeholder')).toHaveLength(3)
  })
})
