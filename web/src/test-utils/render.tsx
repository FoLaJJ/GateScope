import { render } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import type { ReactElement } from 'react'
import { lightTheme } from '@/theme'

interface RenderRouteOptions {
  route?: string
  path?: string
}

function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
        refetchOnWindowFocus: false,
      },
      mutations: {
        retry: false,
      },
    },
  })
}

export function renderWithProviders(ui: ReactElement, route = '/') {
  const queryClient = createTestQueryClient()

  return {
    queryClient,
    ...render(
      <QueryClientProvider client={queryClient}>
        <ConfigProvider locale={zhCN} theme={lightTheme}>
          <MemoryRouter
            initialEntries={[route]}
            future={{
              v7_startTransition: true,
              v7_relativeSplatPath: true,
            }}
          >
            {ui}
          </MemoryRouter>
        </ConfigProvider>
      </QueryClientProvider>,
    ),
  }
}

export function renderRoute(ui: ReactElement, options: RenderRouteOptions = {}) {
  const { route = '/', path = '/' } = options
  return renderWithProviders(
    <Routes>
      <Route path={path} element={ui} />
    </Routes>,
    route,
  )
}
