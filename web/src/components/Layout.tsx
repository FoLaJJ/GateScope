import { useState } from 'react'
import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import { Layout, Menu, Button, Typography, Space } from 'antd'
import {
  DashboardOutlined,
  ScanOutlined,
  CloudServerOutlined,
  BugOutlined,
  AlertOutlined,
  RadarChartOutlined,
  LogoutOutlined,
} from '@ant-design/icons'
import { useAuthStore } from '@/store/auth'
import { useWSInvalidation } from '@/hooks/useWSInvalidation'

const { Header, Sider, Content } = Layout

const menuItems = [
  { key: '/', icon: <DashboardOutlined />, label: '态势大屏' },
  { key: '/tasks', icon: <ScanOutlined />, label: '扫描任务' },
  { key: '/assets', icon: <CloudServerOutlined />, label: '资产管理' },
  { key: '/vulnerabilities', icon: <BugOutlined />, label: '漏洞列表' },
  { key: '/alerts', icon: <AlertOutlined />, label: '告警中心' },
  { key: '/intel', icon: <RadarChartOutlined />, label: '情报中心' },
]

export default function AppLayout() {
  const [collapsed, setCollapsed] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  const { username, logout } = useAuthStore()

  useWSInvalidation()

  const firstPathSegment = location.pathname.split('/').filter(Boolean)[0]
  const selectedKey = firstPathSegment ? `/${firstPathSegment}` : '/'

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider collapsible collapsed={collapsed} onCollapse={setCollapsed} theme="dark">
        <div style={{ padding: '16px', textAlign: 'center' }}>
          <Typography.Title level={4} style={{ color: '#fff', margin: 0, fontSize: collapsed ? 14 : 18 }}>
            {collapsed ? 'GS' : 'GateScope'}
          </Typography.Title>
        </div>
        <Menu
          theme="dark"
          selectedKeys={[location.pathname === '/' ? '/' : selectedKey]}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
        />
      </Sider>
      <Layout>
        <Header
          style={{
            padding: '0 24px',
            background: '#fff',
            display: 'flex',
            justifyContent: 'flex-end',
            alignItems: 'center',
            boxShadow: '0 1px 4px rgba(0,0,0,0.08)',
          }}
        >
          <Space>
            <Typography.Text>{username}</Typography.Text>
            <Button
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
        <Content style={{ margin: 16, padding: 24, background: '#fff', borderRadius: 8, minHeight: 360 }}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  )
}
