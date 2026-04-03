import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import Intel from './Intel'
import { useFOFAImport, useFOFASearch } from '@/api/intel'
import { makeIntelResult, makeTask } from '@/test-utils/fixtures'
import { renderWithProviders } from '@/test-utils/render'

vi.mock('@/api/intel', () => ({
  useFOFASearch: vi.fn(),
  useFOFAImport: vi.fn(),
}))

describe('Intel page', () => {
  it('auto-searches once when URL contains query params', async () => {
    const searchMutation = {
      mutate: vi.fn(),
      data: { data: [], total: 0 },
      isPending: false,
      isSuccess: false,
      isError: false,
    }

    vi.mocked(useFOFASearch).mockReturnValue(searchMutation as never)
    vi.mocked(useFOFAImport).mockReturnValue({
      mutateAsync: vi.fn(),
      isPending: false,
    } as never)

    renderWithProviders(
      <Routes>
        <Route path="/intel" element={<Intel />} />
      </Routes>,
      '/intel?query=app%3D%22openclaw%22&limit=50',
    )

    await waitFor(() => {
      expect(searchMutation.mutate).toHaveBeenCalledTimes(1)
      expect(searchMutation.mutate).toHaveBeenCalledWith({
        query: 'app="openclaw"',
        limit: 50,
      })
    })
  })

  it('disables import button when there are no results', () => {
    vi.mocked(useFOFASearch).mockReturnValue({
      mutate: vi.fn(),
      data: { data: [], total: 0 },
      isPending: false,
      isSuccess: true,
      isError: false,
    } as never)
    vi.mocked(useFOFAImport).mockReturnValue({
      mutateAsync: vi.fn(),
      isPending: false,
    } as never)

    renderWithProviders(
      <Routes>
        <Route path="/intel" element={<Intel />} />
      </Routes>,
      '/intel',
    )

    expect(screen.getByRole('button', { name: /导入并创建任务/ })).toBeDisabled()
  })

  it('renders search results and navigates after successful import', async () => {
    const user = userEvent.setup()
    const importMutation = {
      mutateAsync: vi.fn().mockResolvedValue({
        task: makeTask({ id: 'task-99' }),
        targets: 1,
        message: 'Created task with 1 unique targets from FOFA',
      }),
      isPending: false,
    }

    vi.mocked(useFOFASearch).mockReturnValue({
      mutate: vi.fn(),
      data: {
        data: [makeIntelResult({ host: 'search.example.com' })],
        total: 1,
      },
      isPending: false,
      isSuccess: true,
      isError: false,
    } as never)
    vi.mocked(useFOFAImport).mockReturnValue(importMutation as never)

    renderWithProviders(
      <Routes>
        <Route path="/intel" element={<Intel />} />
        <Route path="/tasks/:id" element={<div>task detail page</div>} />
      </Routes>,
      '/intel',
    )

    expect(screen.getByText('search.example.com')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /导入并创建任务/ })).toBeEnabled()

    await user.click(screen.getByRole('button', { name: /导入并创建任务/ }))

    await screen.findByText('task detail page')
    expect(importMutation.mutateAsync).toHaveBeenCalled()
  })
})
