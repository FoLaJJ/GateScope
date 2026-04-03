import { useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { Card, Descriptions, Tag, Progress, Table, Button, Space, Typography, Tabs, Spin, Timeline, Alert } from 'antd'
import { ArrowLeftOutlined, DownloadOutlined, ReloadOutlined } from '@ant-design/icons'
import { useTask, useTaskEvents } from '@/api/tasks'
import { useAssetList } from '@/api/assets'
import { useVulnList } from '@/api/vulns'
import { useRuleCatalog } from '@/api/rules'
import { exportExcel } from '@/api/reports'
import StatusBadge from '@/components/StatusBadge'
import RiskTag from '@/components/RiskTag'
import AuthTag from '@/components/AuthTag'
import StatCards from '@/components/StatCards'
import { CHECK_TYPE_LABELS } from '@/constants/check'
import { extractVersionContext } from '@/utils/vuln'
import type { Asset, Vulnerability } from '@/types'

export default function TaskDetail() {
  const { id } = useParams<{ id: string }>()

  const { data: task, isLoading, refetch } = useTask(id!)
  const { data: eventsData } = useTaskEvents(id!, 1000)
  const { data: assetsData } = useAssetList(id ? { task_id: id, limit: 1000 } : undefined)
  const { data: vulnsData } = useVulnList(id ? { task_id: id, limit: 1000 } : undefined)
  const { data: ruleCatalog } = useRuleCatalog()

  const events = eventsData?.data ?? []
  const assets = assetsData?.data ?? []
  const vulns = vulnsData?.data ?? []
  const eventTotal = eventsData?.total ?? events.length
  const assetTotal = assetsData?.total ?? assets.length
  const vulnTotal = vulnsData?.total ?? vulns.length

  const vulnsByAssetId = useMemo(() => {
    const grouped: Record<string, Vulnerability[]> = {}
    vulns.forEach((vuln) => {
      if (!grouped[vuln.asset_id]) {
        grouped[vuln.asset_id] = []
      }
      grouped[vuln.asset_id].push(vuln)
    })
    return grouped
  }, [vulns])

  if (isLoading) return <Spin size="large" style={{ display: 'block', margin: '100px auto' }} />
  if (!task) return <Typography.Text>任务未找到</Typography.Text>

  const assetColumns = [
    { title: 'IP', dataIndex: 'ip', key: 'ip', width: 130 },
    { title: '端口', dataIndex: 'port', key: 'port', width: 70 },
    {
      title: 'Agent',
      dataIndex: 'agent_type',
      key: 'type',
      width: 100,
      render: (v: string) => <Tag color="blue">{v}</Tag>,
    },
    { title: '版本', dataIndex: 'version', key: 'ver', width: 110 },
    {
      title: '认证',
      dataIndex: 'auth_mode',
      key: 'auth',
      width: 110,
      render: (v: string) => <AuthTag mode={v} />,
    },
    {
      title: '风险',
      dataIndex: 'risk_level',
      key: 'risk',
      width: 80,
      render: (v: string) => <RiskTag level={v} />,
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      key: 'conf',
      width: 80,
      render: (v: number) => `${Math.round(v)}%`,
    },
    {
      title: '漏洞数',
      key: 'vuln_count',
      width: 90,
      render: (_: unknown, record: Asset) => {
        const count = vulnsByAssetId[record.id]?.length ?? 0
        return count > 0 ? <Tag color="red">{count}</Tag> : <Tag>{count}</Tag>
      },
    },
  ]

  const vulnColumns = [
    { title: 'IP', dataIndex: 'asset_ip', key: 'asset_ip', width: 140, render: (v: string | undefined) => v || '-' },
    {
      title: '端口',
      dataIndex: 'asset_port',
      key: 'asset_port',
      width: 80,
      render: (v: number | undefined) => v ?? '-',
    },
    {
      title: 'Agent',
      dataIndex: 'agent_type',
      key: 'agent_type',
      width: 100,
      render: (v: string | undefined) => (v ? <Tag color="blue">{v}</Tag> : '-'),
    },
    { title: 'CVE', dataIndex: 'cve_id', key: 'cve', width: 150, render: (v: string) => v || '-' },
    { title: '标题', dataIndex: 'title', key: 'title', width: 300, ellipsis: true },
    {
      title: '等级',
      dataIndex: 'severity',
      key: 'sev',
      width: 80,
      render: (v: string) => <RiskTag level={v} />,
    },
    { title: 'CVSS', dataIndex: 'cvss', key: 'cvss', width: 70, render: (v: number) => v?.toFixed(1) },
    {
      title: '判定依据',
      dataIndex: 'check_type',
      key: 'type',
      width: 100,
      render: (v: string) => CHECK_TYPE_LABELS[v] || v,
    },
    { title: '修复', dataIndex: 'remediation', key: 'fix', ellipsis: true },
  ]

  const renderAssetVulns = (asset: Asset) => {
    const relatedVulns = vulnsByAssetId[asset.id] ?? []
    if (relatedVulns.length === 0) {
      return <Typography.Text type="secondary">该资产当前没有关联漏洞。</Typography.Text>
    }

    return (
      <Table
        rowKey="id"
        size="small"
        pagination={false}
        dataSource={relatedVulns}
        columns={[
          { title: 'CVE', dataIndex: 'cve_id', key: 'cve', width: 150, render: (v: string) => v || '-' },
          { title: '标题', dataIndex: 'title', key: 'title', ellipsis: true },
          {
            title: '等级',
            dataIndex: 'severity',
            key: 'severity',
            width: 90,
            render: (v: string) => <RiskTag level={v} />,
          },
          {
            title: '判定依据',
            dataIndex: 'check_type',
            key: 'check_type',
            width: 110,
            render: (v: string) => CHECK_TYPE_LABELS[v] || v,
          },
        ]}
      />
    )
  }

  const renderVulnDetail = (record: Vulnerability) => {
    const versionContext = extractVersionContext(record)
    return (
      <Descriptions size="small" column={2} bordered>
        <Descriptions.Item label="关联资产" span={2}>
          {record.asset_label || '-'}
        </Descriptions.Item>
        <Descriptions.Item label="Agent类型">{record.agent_type || '-'}</Descriptions.Item>
        <Descriptions.Item label="资产版本">{record.asset_version || '-'}</Descriptions.Item>
        <Descriptions.Item label="认证模式">
          {record.auth_mode ? <AuthTag mode={record.auth_mode} /> : '-'}
        </Descriptions.Item>
        <Descriptions.Item label="资产风险">
          {record.risk_level ? <RiskTag level={record.risk_level} /> : '-'}
        </Descriptions.Item>
        <Descriptions.Item label="当前版本">
          {versionContext.currentVersion || record.asset_version || '-'}
        </Descriptions.Item>
        <Descriptions.Item label="修复版本">{versionContext.fixedVersion || '-'}</Descriptions.Item>
        <Descriptions.Item label="本地PoC规则">{versionContext.hasLocalPoCRule ? '是' : '否'}</Descriptions.Item>
        <Descriptions.Item label="检测时间">
          {record.detected_at ? new Date(record.detected_at).toLocaleString('zh-CN') : '-'}
        </Descriptions.Item>
        <Descriptions.Item label="完整描述" span={2}>
          {record.description || '-'}
        </Descriptions.Item>
        <Descriptions.Item label="修复建议" span={2}>
          <Typography.Text type="success">{record.remediation || '-'}</Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label="证据" span={2}>
          <Typography.Paragraph
            code
            style={{ marginBottom: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}
            copyable
          >
            {record.evidence || '-'}
          </Typography.Paragraph>
        </Descriptions.Item>
      </Descriptions>
    )
  }

  return (
    <div>
      <Space style={{ marginBottom: 16 }}>
        <Link to="/tasks">
          <Button icon={<ArrowLeftOutlined />}>返回列表</Button>
        </Link>
        <Button icon={<ReloadOutlined />} onClick={() => refetch()}>
          刷新
        </Button>
        {(task.status === 'completed' || task.status === 'cancelled') && (
          <Button icon={<DownloadOutlined />} type="primary" onClick={() => exportExcel(id!)}>
            导出报告
          </Button>
        )}
      </Space>

      <Card style={{ marginBottom: 16 }}>
        <Descriptions title={task.name} column={3} bordered size="small">
          <Descriptions.Item label="状态">
            <StatusBadge status={task.status} />
          </Descriptions.Item>
          <Descriptions.Item label="扫描深度">{task.scan_depth?.toUpperCase()}</Descriptions.Item>
          <Descriptions.Item label="目标数">{task.total_targets}</Descriptions.Item>
          <Descriptions.Item label="已扫描">{task.scanned_targets}</Descriptions.Item>
          <Descriptions.Item label="开放端口">{task.open_ports}</Descriptions.Item>
          <Descriptions.Item label="发现Agent">{task.found_agents}</Descriptions.Item>
          <Descriptions.Item label="发现漏洞">{task.found_vulns}</Descriptions.Item>
          <Descriptions.Item label="创建时间">{task.created_at}</Descriptions.Item>
          <Descriptions.Item label="目标">{task.targets}</Descriptions.Item>
        </Descriptions>
        {task.status === 'running' && (
          <Progress percent={Math.round(task.progress_percent)} style={{ marginTop: 16 }} status="active" />
        )}
        {task.status === 'completed' && <Progress percent={100} style={{ marginTop: 16 }} />}
        {task.error_message && (
          <Typography.Text type="danger" style={{ display: 'block', marginTop: 8 }}>
            错误: {task.error_message}
          </Typography.Text>
        )}
      </Card>

      {ruleCatalog && (
        <Alert
          style={{ marginBottom: 16 }}
          type={ruleCatalog.consistent ? 'info' : 'warning'}
          showIcon
          message={`漏洞规则库更新时间：${ruleCatalog.updated_at || '未标注'}，上游截止：${ruleCatalog.source_cutoff || '未标注'}`}
          description={`内置 ${ruleCatalog.cve_count} 条 CVE 规则，${ruleCatalog.poc_count} 条 PoC 规则。${
            ruleCatalog.consistent ? '当前映射校验通过。' : `当前存在 ${ruleCatalog.issues.length} 条映射告警。`
          }${ruleCatalog.notes ? ` ${ruleCatalog.notes}` : ''}`}
        />
      )}

      <StatCards
        items={[
          { title: '目标总数', value: task.total_targets },
          { title: '开放端口', value: task.open_ports, valueStyle: { color: '#1677ff' } },
          { title: 'Agent实例', value: task.found_agents, valueStyle: { color: '#fa8c16' } },
          { title: '安全漏洞', value: task.found_vulns, valueStyle: { color: '#f5222d' } },
        ]}
      />

      <Tabs
        style={{ marginTop: 16 }}
        items={[
          {
            key: 'assets',
            label: `资产 (${assetTotal})`,
            children: (
              <Table
                columns={assetColumns}
                dataSource={assets}
                rowKey="id"
                size="small"
                pagination={{ pageSize: 10 }}
                expandable={{ expandedRowRender: renderAssetVulns }}
                scroll={{ x: 1100 }}
              />
            ),
          },
          {
            key: 'vulns',
            label: `漏洞 (${vulnTotal})`,
            children: (
              <Table
                columns={vulnColumns}
                dataSource={vulns}
                rowKey="id"
                size="small"
                pagination={{ pageSize: 10 }}
                expandable={{ expandedRowRender: renderVulnDetail }}
                scroll={{ x: 1400 }}
              />
            ),
          },
          {
            key: 'events',
            label: `事件 (${eventTotal})`,
            children: (
              <Timeline
                items={events.map((e) => ({
                  color: e.event_type.includes('vuln') ? 'red' : 'blue',
                  children: (
                    <>
                      <Typography.Text type="secondary">{e.event_time}</Typography.Text> <Tag>{e.event_type}</Tag>{' '}
                      {e.summary}
                    </>
                  ),
                }))}
              />
            ),
          },
        ]}
      />
    </div>
  )
}
