import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Modal } from 'antd'
import { Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import Tasks from './Tasks'
import { useCreateTask, useDeleteTask, useStartTask, useStopTask, useTaskList } from '@/api/tasks'
import { exportExcel } from '@/api/reports'
import { useImportTargets } from '@/api/targets'
import { makeTask } from '@/test-utils/fixtures'
import LocationDisplay from '@/test-utils/LocationDisplay'
import { renderWithProviders } from '@/test-utils/render'

vi.mock('@/api/tasks', () => ({
  useTaskList: vi.fn(),
  useCreateTask: vi.fn(),
  useStartTask: vi.fn(),
  useStopTask: vi.fn(),
  useDeleteTask: vi.fn(),
}))

vi.mock('@/api/reports', () => ({
  exportExcel: vi.fn(),
}))

vi.mock('@/api/targets', () => ({
  useImportTargets: vi.fn(),
}))

function createMutationMock() {
  return {
    mutate: vi.fn(),
    mutateAsync: vi.fn(),
    isPending: false,
    reset: vi.fn(),
  }
}

describe('Tasks page', () => {
  const createTaskMutation = createMutationMock()
  const startTaskMutation = createMutationMock()
  const stopTaskMutation = createMutationMock()
  const deleteTaskMutation = createMutationMock()
  const importTargetsMutation = createMutationMock()

  beforeEach(() => {
    vi.mocked(useCreateTask).mockReturnValue(createTaskMutation as never)
    vi.mocked(useStartTask).mockReturnValue(startTaskMutation as never)
    vi.mocked(useStopTask).mockReturnValue(stopTaskMutation as never)
    vi.mocked(useDeleteTask).mockReturnValue(deleteTaskMutation as never)
    vi.mocked(useImportTargets).mockReturnValue({
      ...importTargetsMutation,
      data: undefined,
    } as never)
  })

  it('uses URL filters and exposes report download', async () => {
    const user = userEvent.setup()
    vi.mocked(useTaskList).mockReturnValue({
      data: {
        data: [
          makeTask({ id: 'task-running', name: '运行中任务', status: 'running' }),
          makeTask({ id: 'task-done', name: '已完成任务', status: 'completed' }),
        ],
        total: 2,
      },
      isLoading: false,
    } as never)

    renderWithProviders(
      <Routes>
        <Route
          path="/tasks"
          element={
            <>
              <Tasks />
              <LocationDisplay />
            </>
          }
        />
      </Routes>,
      '/tasks?status=running',
    )

    expect(useTaskList).toHaveBeenCalledWith(
      expect.objectContaining({
        status: 'running',
      }),
    )
    expect(screen.getByText('运行中任务')).toBeInTheDocument()
    expect(screen.getByText('已完成任务')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /下载报告/ })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /下载报告/ }))
    expect(exportExcel).toHaveBeenCalledWith('task-done')

    await user.click(screen.getByRole('button', { name: '清空筛选' }))

    await waitFor(() => {
      expect(screen.getByTestId('location-display')).not.toHaveTextContent('status=')
    })
  }, 20000,)

  it('opens create modal and confirms before overriding imported targets', async () => {
    const user = userEvent.setup()
    const confirmSpy = vi.spyOn(Modal, 'confirm').mockImplementation(() => ({ destroy: vi.fn(), update: vi.fn() }) as never)

    vi.mocked(useTaskList).mockReturnValue({
      data: {
        data: [],
        total: 0,
      },
      isLoading: false,
    } as never)
    importTargetsMutation.mutateAsync.mockResolvedValue({
      targets: '2.2.2.2',
      count: 1,
      message: 'Parsed 1 targets from file',
    })

    renderWithProviders(
      <Routes>
        <Route path="/tasks" element={<Tasks />} />
      </Routes>,
      '/tasks',
    )

    await user.click(screen.getByRole('button', { name: /新建任务/ }))
    expect(screen.getByText('新建扫描任务')).toBeInTheDocument()

    await user.type(screen.getByPlaceholderText('192.168.1.0/24, 10.0.0.1'), '1.1.1.1')

    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    expect(fileInput).toBeTruthy()

    await user.upload(fileInput, new File(['2.2.2.2'], 'targets.txt', { type: 'text/plain' }))

    await waitFor(() => {
      expect(importTargetsMutation.mutateAsync).toHaveBeenCalled()
      expect(confirmSpy).toHaveBeenCalled()
    })
  })
})
