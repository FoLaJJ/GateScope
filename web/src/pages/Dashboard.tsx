import React from 'react'
import { Link } from 'react-router-dom'
import { Card, Col, Row, Typography, Tag, Space, List, Tooltip, Skeleton } from 'antd'
import { ScanOutlined, CloudServerOutlined, BugOutlined, WarningOutlined, ArrowRightOutlined } from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { useDashboardStats } from '@/api/dashboard'
import { useTaskList } from '@/api/tasks'
import { useVulnList } from '@/api/vulns'
import StatCards from '@/components/StatCards'
import StatusBadge from '@/components/StatusBadge'
import RiskTag from '@/components/RiskTag'
import { RISK_LABELS, RISK_LEVELS } from '@/constants'
import { displayCVSS, displayUpperUnknown } from '@/utils/display'
import { describeIdentifierState, getPreferredDescription, listVulnerabilityIdentifiers } from '@/utils/vuln'
import type { Task, Vulnerability } from '@/types'

export default function Dashboard() {
  const chartPalette = {
    primary: '#2563eb',
    deep: '#0f766e',
    accent: '#b7791f',
    danger: '#b42318',
  }
  const assetRiskChartColors = {
    critical: '#b42318',
    high: '#d92d20',
    medium: '#f5b301',
    low: '#2563eb',
    info: '#039855',
  } as const
  const vulnSeverityChartColors = {
    critical: '#b42318',
    high: '#d92d20',
    medium: '#f5b301',
    low: '#12b76a',
    info: '#039855',
  } as const

  const { data: stats, isLoading: statsLoading } = useDashboardStats()
  const { data: tasksData } = useTaskList({ limit: 5 })
  const { data: vulnsData } = useVulnList({ limit: 8 })

  const recentTasks = tasksData?.data ?? []
  const recentVulns = vulnsData?.data ?? []

  const criticalCount = stats?.risk_distribution?.critical ?? 0
  const highCount = stats?.risk_distribution?.high ?? 0
  const riskyAssets = criticalCount + highCount
  const riskyAssetRatio = stats?.total_assets ? `${Math.round((riskyAssets / stats.total_assets) * 100)}%` : '0%'

  const riskData = RISK_LEVELS.filter((k) => (stats?.risk_distribution?.[k] ?? 0) > 0).map((k) => ({
    name: RISK_LABELS[k],
    value: stats?.risk_distribution?.[k] ?? 0,
    itemStyle: { color: assetRiskChartColors[k] },
  }))

  const sevData = RISK_LEVELS.filter((k) => (stats?.severity_distribution?.[k] ?? 0) > 0).map((k) => ({
    name: RISK_LABELS[k],
    value: stats?.severity_distribution?.[k] ?? 0,
    itemStyle: { color: vulnSeverityChartColors[k] },
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
        itemStyle: { color: chartPalette.primary, borderRadius: [4, 4, 0, 0] },
        barWidth: 40,
      },
    ],
  }

  return (
    <div>
      <section className="dashboard-lead">
        <div className="dashboard-banner">
          <Typography.Title level={5} style={{ margin: 0 }}>
            安全态势总览
          </Typography.Title>
          <Typography.Text className="banner-kicker">Overview</Typography.Text>
          <Typography.Title level={3} style={{ marginTop: 8, marginBottom: 8 }}>
            OpenClaw 暴露面总览
          </Typography.Title>
          <Typography.Paragraph style={{ marginBottom: 0, maxWidth: 720 }}>
            聚合任务、资产和漏洞结果，优先把需要处置的高风险节点推到前台。
          </Typography.Paragraph>
          <div className="hero-chip-row">
            <div className="hero-chip">
              <span>任务总量</span>
              <strong>{stats?.total_tasks ?? 0}</strong>
            </div>
            <div className="hero-chip">
              <span>资产暴露</span>
              <strong>{stats?.total_assets ?? 0}</strong>
            </div>
            <div className="hero-chip">
              <span>漏洞告警</span>
              <strong>{stats?.total_vulns ?? 0}</strong>
            </div>
          </div>
        </div>

        <div className="dashboard-aside">
          <div className="dashboard-signal">
            <span>高风险资产占比</span>
            <strong>{riskyAssetRatio}</strong>
            <Typography.Text type="secondary">超危和高危资产共 {riskyAssets} 台</Typography.Text>
          </div>
          <div className="dashboard-signal">
            <span>最新任务状态</span>
            <strong>{displayUpperUnknown(recentTasks[0]?.status, 'IDLE')}</strong>
            <Typography.Text type="secondary">
              {recentTasks[0]?.name ? `任务 · ${recentTasks[0].name}` : '当前暂无新任务记录'}
            </Typography.Text>
          </div>
        </div>
      </section>

      <StatCards
        loading={statsLoading}
        items={[
          {
            title: '扫描任务',
            value: stats?.total_tasks ?? 0,
            prefix: <ScanOutlined style={{ color: chartPalette.primary }} />,
          },
          {
            title: '发现Agent',
            value: stats?.total_assets ?? 0,
            prefix: <CloudServerOutlined style={{ color: chartPalette.deep }} />,
            valueStyle: { color: chartPalette.deep },
          },
          {
            title: '安全漏洞',
            value: stats?.total_vulns ?? 0,
            prefix: <BugOutlined style={{ color: chartPalette.danger }} />,
            valueStyle: { color: chartPalette.danger },
          },
          {
            title: '高危资产',
            value: riskyAssets,
            prefix: <WarningOutlined style={{ color: chartPalette.accent }} />,
            valueStyle: { color: chartPalette.accent },
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
          <Card title="资产风险分布" size="small" style={{ height: 340 }} className="surface-card dashboard-grid-card">
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
          <Card title="漏洞严重等级" size="small" style={{ height: 340 }} className="surface-card dashboard-grid-card">
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
          <Card title="Agent 类型分布" size="small" style={{ height: 340 }} className="surface-card dashboard-grid-card">
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
                查看全部 <ArrowRightOutlined />
              </Link>
            }
            className="surface-card"
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
                      <Link to={`/tasks/${t.id}`}>{t.name}</Link>
                    }
                    description={
                      <Space size="small">
                        <StatusBadge status={t.status} showIcon={false} />
                        <Tag>{displayUpperUnknown(t.scan_depth)}</Tag>
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
                查看全部 <ArrowRightOutlined />
              </Link>
            }
            className="surface-card"
          >
            <List
              dataSource={recentVulns}
              renderItem={(v: Vulnerability) => {
                const identifiers = listVulnerabilityIdentifiers(v)
                const identifierState = describeIdentifierState(v)
                return (
                  <List.Item>
                    <List.Item.Meta
                      title={
                        <Space size="small">
                          <RiskTag level={v.severity} />
                          <Tooltip title={getPreferredDescription(v)}>
                            <Typography.Text ellipsis style={{ maxWidth: 300 }}>
                              {v.title}
                            </Typography.Text>
                          </Tooltip>
                        </Space>
                      }
                      description={
                        <Space size="small">
                          {identifiers.length > 0
                            ? identifiers.map((identifier) => (
                                <Tag color="geekblue" key={identifier.key}>
                                  <a className="identifier-link" href={identifier.href} target="_blank" rel="noreferrer">
                                    {identifier.label}
                                  </a>
                                </Tag>
                              ))
                            : identifierState && <Tag>{identifierState}</Tag>}
                          <Typography.Text type="secondary">
                            CVSS {displayCVSS(v.cvss)}
                          </Typography.Text>
                        </Space>
                      }
                    />
                  </List.Item>
                )
              }}
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
