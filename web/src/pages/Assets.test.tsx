import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import Assets from './Assets'
import { useAssetList } from '@/api/assets'
import { makeAsset } from '@/test-utils/fixtures'
import LocationDisplay from '@/test-utils/LocationDisplay'
import { renderWithProviders } from '@/test-utils/render'

vi.mock('@/api/assets', () => ({
  useAssetList: vi.fn(),
}))

describe('Assets page', () => {
  it('updates URL search params when searching by IP', async () => {
    const user = userEvent.setup()
    vi.mocked(useAssetList).mockReturnValue({
      data: {
        data: [makeAsset()],
        total: 1,
      },
      isLoading: false,
    } as never)

    renderWithProviders(
      <Routes>
        <Route
          path="/assets"
          element={
            <>
              <Assets />
              <LocationDisplay />
            </>
          }
        />
      </Routes>,
      '/assets',
    )

    await user.type(screen.getByPlaceholderText('搜索IP'), '10.10.10.10{enter}')

    await waitFor(() => {
      expect(screen.getByTestId('location-display')).toHaveTextContent('ip=10.10.10.10')
    })
    expect(useAssetList).toHaveBeenLastCalledWith(
      expect.objectContaining({
        ip: '10.10.10.10',
      }),
    )
  })

  it('renders expanded asset details', async () => {
    vi.mocked(useAssetList).mockReturnValue({
      data: {
        data: [makeAsset({ agent_id: 'agent-expanded' })],
        total: 1,
      },
      isLoading: false,
    } as never)

    const { container } = renderWithProviders(
      <Routes>
        <Route path="/assets" element={<Assets />} />
      </Routes>,
      '/assets',
    )

    const expandButton = container.querySelector('.ant-table-row-expand-icon') as HTMLElement
    expect(expandButton).toBeTruthy()

    fireEvent.click(expandButton)

    expect(await screen.findByText('agent-expanded')).toBeInTheDocument()
    expect(screen.getAllByText('Shanghai')).toHaveLength(2)
  })
})
