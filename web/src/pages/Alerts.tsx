import { useEffect, useState } from 'react'
import type { ColumnsType } from 'antd/es/table'
import {
  Alert,
  Button,
  Card,
  Input,
  Select,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
  message,
} from 'antd'
import {
  DeleteOutlined,
  PlusOutlined,
  ReloadOutlined,
  SendOutlined,
  SaveOutlined,
} from '@ant-design/icons'
import { useAlertHistory, useAlertRules, useTestWebhook, useUpdateAlertRules } from '@/api/alert'
import { getRiskOptions } from '@/constants'
import type { AlertCondition, AlertEventType, AlertRecord, AlertRule } from '@/types'

type EditableAlertRule = AlertRule & { key: string }

const EVENT_OPTIONS: Array<{ label: string; value: AlertEventType }> = [
  { label: '新 Agent 发现', value: 'agent.identified' },
  { label: '漏洞发现', value: 'vuln.detected' },
  { label: '任务完成', value: 'task.completed' },
]

const CONDITION_OPTIONS: Array<{ label: string; value: AlertCondition }> = [
  { label: '始终触发', value: 'always' },
  { label: '新 Agent', value: 'new_agent' },
  { label: '无认证 Agent', value: 'unauth_agent' },
  { label: '漏洞等级不低于阈值', value: 'severity_gte' },
  { label: '风险等级不低于阈值', value: 'risk_gte' },
  { label: '检测到恶意技能', value: 'malicious_skill' },
  { label: '任务完成', value: 'task_completed' },
]

function needsThreshold(condition: AlertCondition) {
  return condition === 'severity_gte' || condition === 'risk_gte'
}

function summarizeRecordData(data: Record<string, unknown>) {
  const entries = Object.entries(data).slice(0, 3)
  if (entries.length === 0) return '-'
  return entries
    .map(([key, value]) => `${key}: ${typeof value === 'string' ? value : JSON.stringify(value)}`)
    .join(' | ')
}

export default function Alerts() {
  const [historyLimit, setHistoryLimit] = useState(100)
  const [draftRules, setDraftRules] = useState<EditableAlertRule[]>([])
  const { data: rules = [], isLoading: rulesLoading, refetch } = useAlertRules()
  const { data: history = [], isLoading: historyLoading } = useAlertHistory(historyLimit)
  const updateRules = useUpdateAlertRules()
  const testWebhook = useTestWebhook()

  useEffect(() => {
    setDraftRules(
      rules.map((rule, index) => ({
        ...rule,
        key: `${rule.name}-${index}`,
      })),
    )
  }, [rules])

  const updateRule = (key: string, patch: Partial<AlertRule>) => {
    setDraftRules((prev) =>
      prev.map((rule) => {
        if (rule.key !== key) return rule

        const nextCondition = patch.condition ?? rule.condition
        return {
          ...rule,
          ...patch,
          threshold: needsThreshold(nextCondition) ? (patch.threshold ?? rule.threshold) || 'high' : '',
        }
      }),
    )
  }

  const handleAddRule = () => {
    setDraftRules((prev) => [
      ...prev,
      {
        key: `new-${Date.now()}`,
        name: `新规则 ${prev.length + 1}`,
        event: 'vuln.detected',
        condition: 'severity_gte',
        threshold: 'high',
        enabled: true,
      },
    ])
  }

  const handleSave = async () => {
    const hasEmptyName = draftRules.some((rule) => !rule.name.trim())
    if (hasEmptyName) {
      message.error('规则名称不能为空')
      return
    }

    const hasMissingThreshold = draftRules.some((rule) => needsThreshold(rule.condition) && !rule.threshold.trim())
    if (hasMissingThreshold) {
      message.error('带阈值的规则必须选择阈值')
      return
    }

    try {
      const payload = draftRules.map(({ key: _key, ...rule }) => ({
        ...rule,
        threshold: needsThreshold(rule.condition) ? rule.threshold : '',
      }))

      await updateRules.mutateAsync(payload)
      message.success('告警规则已更新')
    } catch (e: unknown) {
      if (e instanceof Error && e.message) {
        message.error(e.message)
      }
    }
  }

  const handleTestWebhook = async () => {
    try {
      const result = await testWebhook.mutateAsync()
      message.success(result.message)
    } catch (e: unknown) {
      if (e instanceof Error && e.message) {
        if (e.message.includes('webhook URL not configured')) {
          message.warning('当前未配置 Webhook URL。请先在 _data/config.yaml 中设置 alert.webhook_url，并按需开启 alert.enabled。')
          return
        }

        message.error(e.message)
      }
    }
  }

  const ruleColumns: ColumnsType<EditableAlertRule> = [
    {
      title: '规则名称',
      dataIndex: 'name',
      key: 'name',
      width: 220,
      render: (value: string, record) => (
        <Input value={value} onChange={(event) => updateRule(record.key, { name: event.target.value })} />
      ),
    },
    {
      title: '事件',
      dataIndex: 'event',
      key: 'event',
      width: 180,
      render: (value: AlertEventType, record) => (
        <Select
          value={value}
          style={{ width: '100%' }}
          options={EVENT_OPTIONS}
          onChange={(nextValue) => updateRule(record.key, { event: nextValue })}
        />
      ),
    },
    {
      title: '条件',
      dataIndex: 'condition',
      key: 'condition',
      width: 220,
      render: (value: AlertCondition, record) => (
        <Select
          value={value}
          style={{ width: '100%' }}
          options={CONDITION_OPTIONS}
          onChange={(nextValue) => updateRule(record.key, { condition: nextValue })}
        />
      ),
    },
    {
      title: '阈值',
      dataIndex: 'threshold',
      key: 'threshold',
      width: 160,
      render: (value: string, record) =>
        needsThreshold(record.condition) ? (
          <Select
            value={value || 'high'}
            style={{ width: '100%' }}
            options={getRiskOptions()}
            onChange={(nextValue) => updateRule(record.key, { threshold: nextValue })}
          />
        ) : (
          <Typography.Text type="secondary">不适用</Typography.Text>
        ),
    },
    {
      title: '启用',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 90,
      align: 'center',
      render: (value: boolean, record) => (
        <Switch checked={value} onChange={(checked) => updateRule(record.key, { enabled: checked })} />
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 90,
      align: 'center',
      render: (_value, record) => (
        <Button
          danger
          type="text"
          icon={<DeleteOutlined />}
          onClick={() => setDraftRules((prev) => prev.filter((rule) => rule.key !== record.key))}
        />
      ),
    },
  ]

  const historyColumns: ColumnsType<AlertRecord> = [
    {
      title: '事件类型',
      dataIndex: 'event_type',
      key: 'event_type',
      width: 160,
      render: (value: AlertEventType) => {
        const match = EVENT_OPTIONS.find((item) => item.value === value)
        return <Tag color="blue">{match?.label || value}</Tag>
      },
    },
    {
      title: '命中规则',
      dataIndex: 'rule_name',
      key: 'rule_name',
      width: 180,
    },
    {
      title: '发送状态',
      dataIndex: 'sent',
      key: 'sent',
      width: 120,
      render: (value: boolean) => <Tag color={value ? 'success' : 'error'}>{value ? '已发送' : '发送失败'}</Tag>,
    },
    {
      title: '数据摘要',
      dataIndex: 'data',
      key: 'data',
      render: (value: Record<string, unknown>) => summarizeRecordData(value || {}),
    },
    {
      title: '错误信息',
      dataIndex: 'error',
      key: 'error',
      width: 240,
      ellipsis: true,
      render: (value?: string) => value || '-',
    },
    {
      title: '时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (value: string) => new Date(value).toLocaleString('zh-CN'),
    },
  ]

  return (
    <div>
      <Typography.Title level={4}>告警中心</Typography.Title>

      <Tabs
        items={[
          {
            key: 'rules',
            label: '告警规则',
            children: (
              <Card
                extra={
                  <Space>
                    <Button icon={<ReloadOutlined />} onClick={() => refetch()}>
                      刷新
                    </Button>
                    <Button icon={<SendOutlined />} onClick={handleTestWebhook} loading={testWebhook.isPending}>
                      测试 Webhook
                    </Button>
                    <Button type="primary" icon={<SaveOutlined />} onClick={handleSave} loading={updateRules.isPending}>
                      保存规则
                    </Button>
                  </Space>
                }
              >
                <Alert
                  type="info"
                  showIcon
                  style={{ marginBottom: 12 }}
                  message="测试 Webhook 依赖后端告警配置；如果未设置 alert.webhook_url，会提示未配置而不会真正发出请求。"
                />
                <Alert
                  type="warning"
                  showIcon
                  style={{ marginBottom: 16 }}
                  message="保存会整体覆盖当前规则列表，请确认后再提交。"
                />
                <Space style={{ marginBottom: 16 }}>
                  <Button icon={<PlusOutlined />} onClick={handleAddRule}>
                    新增规则
                  </Button>
                  <Typography.Text type="secondary">
                    当前共 {draftRules.length} 条规则
                  </Typography.Text>
                </Space>
                <Table
                  rowKey="key"
                  loading={rulesLoading}
                  columns={ruleColumns}
                  dataSource={draftRules}
                  pagination={false}
                  scroll={{ x: 980 }}
                />
              </Card>
            ),
          },
          {
            key: 'history',
            label: '告警历史',
            children: (
              <Card>
                <Space style={{ marginBottom: 16 }} wrap>
                  <Typography.Text type="secondary">最近记录数</Typography.Text>
                  <Select
                    value={historyLimit}
                    style={{ width: 120 }}
                    options={[
                      { label: '最近 50 条', value: 50 },
                      { label: '最近 100 条', value: 100 },
                      { label: '最近 200 条', value: 200 },
                    ]}
                    onChange={(value) => setHistoryLimit(value)}
                  />
                </Space>
                <Table
                  rowKey="id"
                  loading={historyLoading}
                  columns={historyColumns}
                  dataSource={history}
                  expandable={{
                    expandedRowRender: (record) => (
                      <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                        {JSON.stringify(record.data, null, 2)}
                      </pre>
                    ),
                  }}
                  pagination={{
                    pageSize: 20,
                    showSizeChanger: true,
                    showTotal: (total) => `当前已加载 ${total} 条`,
                  }}
                  scroll={{ x: 1100 }}
                />
              </Card>
            ),
          },
        ]}
      />
    </div>
  )
}
