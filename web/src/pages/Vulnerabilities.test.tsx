import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import Vulnerabilities from './Vulnerabilities'
import { useVulnList } from '@/api/vulns'
import { makeVulnerability } from '@/test-utils/fixtures'
import LocationDisplay from '@/test-utils/LocationDisplay'
import { renderWithProviders } from '@/test-utils/render'

vi.mock('@/api/vulns', () => ({
  useVulnList: vi.fn(),
}))

describe('Vulnerabilities page', () => {
  it('updates URL search params when searching by CVE', async () => {
    const user = userEvent.setup()
    vi.mocked(useVulnList).mockReturnValue({
      data: {
        data: [makeVulnerability()],
        total: 1,
      },
      isLoading: false,
    } as never)

    renderWithProviders(
      <Routes>
        <Route
          path="/vulnerabilities"
          element={
            <>
              <Vulnerabilities />
              <LocationDisplay />
            </>
          }
        />
      </Routes>,
      '/vulnerabilities',
    )

    await user.type(screen.getByPlaceholderText('搜索CVE编号'), 'CVE-2026-4242{enter}')

    await waitFor(() => {
      expect(screen.getByTestId('location-display')).toHaveTextContent('cve_id=CVE-2026-4242')
    })
    expect(useVulnList).toHaveBeenLastCalledWith(
      expect.objectContaining({
        cve_id: 'CVE-2026-4242',
      }),
    )
  })

  it('renders expanded vulnerability details', async () => {
    vi.mocked(useVulnList).mockReturnValue({
      data: {
        data: [makeVulnerability({ description: '展开后的漏洞描述' })],
        total: 1,
      },
      isLoading: false,
    } as never)

    const { container } = renderWithProviders(
      <Routes>
        <Route path="/vulnerabilities" element={<Vulnerabilities />} />
      </Routes>,
      '/vulnerabilities',
    )

    const expandButton = container.querySelector('.ant-table-row-expand-icon') as HTMLElement
    expect(expandButton).toBeTruthy()

    fireEvent.click(expandButton)

    expect(await screen.findByText('展开后的漏洞描述')).toBeInTheDocument()
    expect(screen.getAllByText('升级到最新版本')).toHaveLength(2)
  })
})
