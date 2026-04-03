import React from 'react'
import { Result, Button, Typography } from 'antd'

interface Props {
  children: React.ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
}

export class ErrorBoundary extends React.Component<Props, State> {
  state: State = { hasError: false, error: null }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('[ErrorBoundary]', error, info.componentStack)
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null })
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
          <Result
            status="error"
            title="页面发生错误"
            subTitle="请刷新页面重试，如果问题持续存在请联系管理员"
            extra={[
              <Button key="retry" type="primary" onClick={this.handleReset}>
                重试
              </Button>,
              <Button key="home" onClick={() => (window.location.href = '/')}>
                返回首页
              </Button>,
            ]}
          >
            {import.meta.env.DEV && this.state.error && (
              <Typography.Paragraph>
                <Typography.Text code style={{ whiteSpace: 'pre-wrap', fontSize: 12 }}>
                  {this.state.error.message}
                  {'\n'}
                  {this.state.error.stack}
                </Typography.Text>
              </Typography.Paragraph>
            )}
          </Result>
        </div>
      )
    }
    return this.props.children
  }
}
