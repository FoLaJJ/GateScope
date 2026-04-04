import { useState } from 'react'
import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import { Layout, Menu, Button, Typography, Space } from 'antd'
import {
  DashboardOutlined,
  ScanOutlined,
  CloudServerOutlined,
  BugOutlined,
  LogoutOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons'
import { useAuthStore } from '@/store/auth'
import { useWSInvalidation } from '@/hooks/useWSInvalidation'
import { useRuntimeSync } from '@/hooks/useRuntimeSync'

const { Header, Sider, Content } = Layout

const menuItems = [
  { key: '/', icon: <DashboardOutlined />, label: '态势大屏' },
  { key: '/tasks', icon: <ScanOutlined />, label: '扫描任务' },
  { key: '/assets', icon: <CloudServerOutlined />, label: '资产管理' },
  { key: '/vulnerabilities', icon: <BugOutlined />, label: '漏洞列表' },
]

const headerMeta: Record<string, { kicker: string; title: string }> = {
  '/': { kicker: 'Overview', title: '暴露面概览' },
  '/tasks': { kicker: 'Tasks', title: '扫描任务' },
  '/assets': { kicker: 'Assets', title: '资产管理' },
  '/vulnerabilities': { kicker: 'Vulnerabilities', title: '漏洞清单' },
}

export default function AppLayout() {
  const [collapsed, setCollapsed] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  const { username, logout } = useAuthStore()

  useWSInvalidation()
  useRuntimeSync()

  const firstPathSegment = location.pathname.split('/').filter(Boolean)[0]
  const selectedKey = firstPathSegment ? `/${firstPathSegment}` : '/'
  const meta = headerMeta[selectedKey] ?? { kicker: 'GateScope', title: 'OpenClaw 暴露面控制台' }

  return (
    <Layout className="app-shell">
      <Sider collapsible collapsed={collapsed} onCollapse={setCollapsed} theme="dark" className="app-sider" width={248}>
        <div className="app-brand">
          <div className="app-brand-mark">
            <ThunderboltOutlined />
          </div>
          {!collapsed && (
            <div>
              <Typography.Title level={4} className="app-brand-title">
                GateScope
              </Typography.Title>
              <Typography.Text className="app-brand-subtitle">Asset Security Console</Typography.Text>
            </div>
          )}
        </div>
        <Menu
          theme="dark"
          className="app-menu"
          selectedKeys={[location.pathname === '/' ? '/' : selectedKey]}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
        />
      </Sider>
      <Layout>
        <Header className="app-header">
          <div className="app-header-meta">
            <Typography.Text className="app-header-kicker">{meta.kicker}</Typography.Text>
            <Typography.Title level={4} className="app-header-title">
              {meta.title}
            </Typography.Title>
          </div>
          <Space>
            <Typography.Text className="app-header-user">{username}</Typography.Text>
            <Button
              className="app-header-action"
              icon={<LogoutOutlined />}
              type="text"
              onClick={() => {
                logout()
                navigate('/login')
              }}
            >
              退出
            </Button>
          </Space>
        </Header>
        <Content className="app-content">
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  )
}
