import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Form, Input, Button, Card, Typography, message, Space, Divider, Alert } from 'antd'
import { LockOutlined, UserOutlined, SafetyCertificateOutlined, ThunderboltOutlined } from '@ant-design/icons'
import { login } from '@/api/auth'
import { useAuthStore } from '@/store/auth'

const DEFAULT_USERNAME = 'admin'
const DEFAULT_PASSWORD = 'agentscan'

export default function Login() {
  const [loading, setLoading] = useState(false)
  const [form] = Form.useForm<{ username: string; password: string }>()
  const navigate = useNavigate()
  const setAuth = useAuthStore((s) => s.setAuth)

  const submitLogin = async (username: string, password: string) => {
    setLoading(true)
    try {
      const { token } = await login(username, password)
      setAuth(token, username)
      message.success('登录成功')
      navigate('/')
    } catch {
      message.error('用户名或密码错误')
    } finally {
      setLoading(false)
    }
  }

  const onFinish = async (values: { username: string; password: string }) => {
    await submitLogin(values.username, values.password)
  }

  const handleQuickLogin = async () => {
    form.setFieldsValue({ username: DEFAULT_USERNAME, password: DEFAULT_PASSWORD })
    await submitLogin(DEFAULT_USERNAME, DEFAULT_PASSWORD)
  }

  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '100vh',
        padding: 24,
        background: 'linear-gradient(180deg, #f7f9fc 0%, #eef3f8 100%)',
      }}
    >
      <Card
        style={{
          width: 440,
          borderRadius: 20,
          border: '1px solid #dbe2ea',
          background: '#ffffff',
          boxShadow: '0 18px 40px rgba(15, 23, 42, 0.08)',
        }}
        variant="borderless"
      >
        <Space direction="vertical" size="large" style={{ width: '100%', textAlign: 'center' }}>
          <SafetyCertificateOutlined style={{ fontSize: 40, color: 'var(--gs-primary)' }} />
          <Typography.Title level={3} style={{ margin: 0 }}>
            GateScope
          </Typography.Title>
          <Typography.Text type="secondary">面向 OpenClaw 暴露面的轻量审计控制台</Typography.Text>
        </Space>
        <Alert
          style={{ marginTop: 24 }}
          type="info"
          showIcon
          message="默认账号已填好"
          description={`用户名: ${DEFAULT_USERNAME}  密码: ${DEFAULT_PASSWORD}`}
        />
        <Form
          form={form}
          name="login"
          onFinish={onFinish}
          initialValues={{ username: DEFAULT_USERNAME, password: DEFAULT_PASSWORD }}
          style={{ marginTop: 24 }}
          size="large"
        >
          <Form.Item name="username" rules={[{ required: true, message: '请输入用户名' }]}>
            <Input prefix={<UserOutlined />} placeholder="用户名" autoComplete="username" />
          </Form.Item>
          <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
            <Input.Password prefix={<LockOutlined />} placeholder="密码" autoComplete="current-password" />
          </Form.Item>
          <Form.Item style={{ marginBottom: 12 }}>
            <Button
              aria-label="一键登录"
              icon={<ThunderboltOutlined aria-hidden="true" />}
              type="primary"
              onClick={handleQuickLogin}
              loading={loading}
              block
            >
              一键登录
            </Button>
          </Form.Item>
          <Divider style={{ margin: '12px 0' }}>或</Divider>
          <Form.Item>
            <Button htmlType="submit" loading={loading} block>
              使用当前输入登录
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </div>
  )
}
