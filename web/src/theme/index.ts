import type { ThemeConfig } from 'antd'

export const lightTheme: ThemeConfig = {
  token: {
    colorPrimary: '#2563eb',
    colorInfo: '#2563eb',
    colorSuccess: '#15803d',
    colorWarning: '#b7791f',
    colorError: '#b42318',
    borderRadius: 16,
    colorBgContainer: '#ffffff',
    colorBgLayout: '#f3f6f9',
    colorBorder: '#dbe2ea',
    colorText: '#17212f',
    colorTextSecondary: '#667085',
    fontFamily:
      "'IBM Plex Sans', 'PingFang SC', 'Segoe UI', 'Noto Sans SC', sans-serif",
  },
  components: {
    Layout: {
      siderBg: '#0f172a',
      headerBg: '#ffffff',
    },
    Table: {
      headerBg: '#f8fafc',
      borderColor: '#e2e8f0',
    },
    Card: {
      borderRadiusLG: 20,
    },
    Button: {
      borderRadius: 12,
    },
    Input: {
      borderRadius: 12,
    },
    Select: {
      borderRadius: 12,
    },
  },
}

export const darkTheme: ThemeConfig = {
  token: {
    colorPrimary: '#ad4d31',
    borderRadius: 6,
    colorBgContainer: '#141414',
    colorBgLayout: '#000000',
    fontFamily:
      "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, 'Noto Sans SC', sans-serif",
  },
  algorithm: undefined, // Will be set to theme.darkAlgorithm in main.tsx
  components: {
    Layout: {
      siderBg: '#001529',
    },
  },
}
