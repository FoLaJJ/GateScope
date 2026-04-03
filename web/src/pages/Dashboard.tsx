import React from 'react'
import { Link } from 'react-router-dom'
import { Card, Col, Row, Typography, Tag, Space, List, Tooltip, Skeleton } from 'antd'
import { ScanOutlined, CloudServerOutlined, BugOutlined, WarningOutlined } from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { useDashboardStats } from '@/api/dashboard'
import { useTaskList } from '@/api/tasks'
import { useVulnList } from '@/api/vulns'
import StatCards from '@/components/StatCards'
import StatusBadge from '@/components/StatusBadge'
import RiskTag from '@/components/RiskTag'
import { RISK_COLORS, RISK_LABELS, RISK_LEVELS } from '@/constants'
import type { Task, Vulnerability } from '@/types'

export default function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useDashboardStats()
  const { data: tasksData } = useTaskList({ limit: 5 })
  const { data: vulnsData } = useVulnList({ limit: 8 })

  const recentTasks = tasksData?.data ?? []
  const recentVulns = vulnsData?.data ?? []

  const criticalCount = stats?.risk_distribution?.critical ?? 0
  const highCount = stats?.risk_distribution?.high ?? 0

  const riskData = RISK_LEVELS.filter((k) => (stats?.risk_distribution?.[k] ?? 0) > 0).map((k) => ({
    name: RISK_LABELS[k],
    value: stats?.risk_distribution?.[k] ?? 0,
    itemStyle: { color: RISK_COLORS[k] },
  }))

  const sevData = RISK_LEVELS.filter((k) => (stats?.severity_distribution?.[k] ?? 0) > 0).map((k) => ({
    name: RISK_LABELS[k],
    value: stats?.severity_distribution?.[k] ?? 0,
    itemStyle: { color: RISK_COLORS[k] },
  }))

  const agentData = Object.entries(stats?.agent_type_distribution ?? {})

  const riskGaugeOption = {
    tooltip: { trigger: 'item' as const, formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 0, itemWidth: 12, itemHeight: 12, textStyle: { fontSize: 12 } },
    series: [
      {
        type: 'pie',
        radius: ['45%', '72%'],
        center: ['50%', '45%'],
        data: riskData,
        label: { show: false },
        emphasis: { label: { show: true, fontSize: 14, fontWeight: 'bold' } },
        itemStyle: { borderRadius: 4, borderColor: '#fff', borderWidth: 2 },
      },
    ],
  }

  const sevBarOption = {
    tooltip: { trigger: 'axis' as const },
    grid: { left: 60, right: 20, top: 20, bottom: 30 },
    xAxis: { type: 'value' as const },
    yAxis: {
      type: 'category' as const,
      data: sevData.map((d) => d.name).reverse(),
      axisLabel: { fontSize: 12 },
    },
    series: [
      {
        type: 'bar',
        data: sevData.map((d) => ({ value: d.value, itemStyle: d.itemStyle })).reverse(),
        barWidth: 20,
        itemStyle: { borderRadius: [0, 4, 4, 0] },
      },
    ],
  }

  const agentBarOption = {
    tooltip: {},
    grid: { left: 40, right: 20, top: 20, bottom: 40 },
    xAxis: { type: 'category' as const, data: agentData.map(([k]) => k), axisLabel: { rotate: 30 } },
    yAxis: { type: 'value' as const },
    series: [
      {
        type: 'bar',
        data: agentData.map(([, v]) => v),
        itemStyle: { color: '#1677ff', borderRadius: [4, 4, 0, 0] },
        barWidth: 40,
      },
    ],
  }

  return (
    <div>
      <Typography.Title level={4} style={{ marginBottom: 20 }}>
        安全态势总览
      </Typography.Title>

      <StatCards
        loading={statsLoading}
        items={[
          {
            title: '扫描任务',
            value: stats?.total_tasks ?? 0,
            prefix: <ScanOutlined style={{ color: '#722ed1' }} />,
          },
          {
            title: '发现Agent',
            value: stats?.total_assets ?? 0,
            prefix: <CloudServerOutlined style={{ color: '#1677ff' }} />,
            valueStyle: { color: '#1677ff' },
          },
          {
            title: '安全漏洞',
            value: stats?.total_vulns ?? 0,
            prefix: <BugOutlined style={{ color: '#f5222d' }} />,
            valueStyle: { color: '#f5222d' },
          },
          {
            title: '高危资产',
            value: criticalCount + highCount,
            prefix: <WarningOutlined style={{ color: '#fa8c16' }} />,
            valueStyle: { color: '#fa8c16' },
            suffix: stats?.total_assets ? (
              <Typography.Text type="secondary" style={{ fontSize: 14 }}>
                / {stats.total_assets}
              </Typography.Text>
            ) : null,
          },
        ]}
      />

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} md={8}>
          <Card title="资产风险分布" size="small" style={{ height: 340 }}>
            {statsLoading ? (
              <Skeleton active />
            ) : riskData.length > 0 ? (
              <ReactECharts option={riskGaugeOption} style={{ height: 280 }} />
            ) : (
              <EmptyChart />
            )}
          </Card>
        </Col>
        <Col xs={24} md={8}>
          <Card title="漏洞严重等级" size="small" style={{ height: 340 }}>
            {statsLoading ? (
              <Skeleton active />
            ) : sevData.length > 0 ? (
              <ReactECharts option={sevBarOption} style={{ height: 280 }} />
            ) : (
              <EmptyChart />
            )}
          </Card>
        </Col>
        <Col xs={24} md={8}>
          <Card title="Agent 类型分布" size="small" style={{ height: 340 }}>
            {statsLoading ? (
              <Skeleton active />
            ) : agentData.length > 0 ? (
              <ReactECharts option={agentBarOption} style={{ height: 280 }} />
            ) : (
              <EmptyChart />
            )}
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} md={12}>
          <Card
            title={
              <Space>
                <ScanOutlined /> 最近任务
              </Space>
            }
            size="small"
            extra={
              <Link to="/tasks">
                <Typography.Link>查看全部</Typography.Link>
              </Link>
            }
          >
            <List
              dataSource={recentTasks}
              renderItem={(t: Task) => (
                <List.Item
                  actions={[
                    <Typography.Text type="secondary" key="time">
                      {t.created_at ? new Date(t.created_at).toLocaleDateString('zh-CN') : ''}
                    </Typography.Text>,
                  ]}
                >
                  <List.Item.Meta
                    title={
                      <Link to={`/tasks/${t.id}`}>
                        <Typography.Link>{t.name}</Typography.Link>
                      </Link>
                    }
                    description={
                      <Space size="small">
                        <StatusBadge status={t.status} showIcon={false} />
                        <Tag>{t.scan_depth?.toUpperCase()}</Tag>
                        {t.found_agents > 0 && <Tag color="blue">{t.found_agents} Agent</Tag>}
                        {t.found_vulns > 0 && <Tag color="red">{t.found_vulns} 漏洞</Tag>}
                      </Space>
                    }
                  />
                </List.Item>
              )}
              locale={{ emptyText: '暂无任务' }}
            />
          </Card>
        </Col>
        <Col xs={24} md={12}>
          <Card
            title={
              <Space>
                <BugOutlined /> 最新漏洞
              </Space>
            }
            size="small"
            extra={
              <Link to="/vulnerabilities">
                <Typography.Link>查看全部</Typography.Link>
              </Link>
            }
          >
            <List
              dataSource={recentVulns}
              renderItem={(v: Vulnerability) => (
                <List.Item>
                  <List.Item.Meta
                    title={
                      <Space size="small">
                        <RiskTag level={v.severity} />
                        <Tooltip title={v.description}>
                          <Typography.Text ellipsis style={{ maxWidth: 300 }}>
                            {v.title}
                          </Typography.Text>
                        </Tooltip>
                      </Space>
                    }
                    description={
                      <Space size="small">
                        {v.cve_id && <Tag color="geekblue">{v.cve_id}</Tag>}
                        <Typography.Text type="secondary">CVSS {v.cvss?.toFixed(1)}</Typography.Text>
                      </Space>
                    }
                  />
                </List.Item>
              )}
              locale={{ emptyText: '暂无漏洞' }}
            />
          </Card>
        </Col>
      </Row>
    </div>
  )
}

const EmptyChart = React.memo(() => (
  <div style={{ textAlign: 'center', padding: 60, color: '#999' }}>暂无数据</div>
))
