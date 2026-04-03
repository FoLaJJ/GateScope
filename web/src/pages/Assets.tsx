import { useEffect, useMemo, useState } from 'react'
import type { ColumnsType } from 'antd/es/table'
import { Table, Typography, Input, Select, Space, Descriptions, Badge, Button } from 'antd'
import { CloudServerOutlined, SafetyCertificateOutlined, WarningOutlined, SearchOutlined } from '@ant-design/icons'
import { useAssetList } from '@/api/assets'
import StatCards from '@/components/StatCards'
import RiskTag from '@/components/RiskTag'
import AuthTag from '@/components/AuthTag'
import { getRiskOptions, confidenceColor } from '@/constants'
import { useURLQueryState } from '@/hooks/useURLQueryState'
import type { Asset, AssetListParams } from '@/types'

type AssetQueryState = {
  page: number
  limit: number
  ip: string
  agent_type: string
  risk_level: string
}

const ASSET_QUERY_DEFAULTS: AssetQueryState = {
  page: 1,
  limit: 20,
  ip: '',
  agent_type: '',
  risk_level: '',
}

const EMPTY_ASSETS: Asset[] = []

export default function Assets() {
  const { params, setParams, resetParams } = useURLQueryState(ASSET_QUERY_DEFAULTS)
  const [searchIP, setSearchIP] = useState(params.ip)

  useEffect(() => {
    setSearchIP(params.ip)
  }, [params.ip])

  const queryParams: AssetListParams = {
    page: params.page,
    limit: params.limit,
    ip: params.ip || undefined,
    agent_type: params.agent_type || undefined,
    risk_level: params.risk_level ? (params.risk_level as Asset['risk_level']) : undefined,
  }

  const { data, isLoading } = useAssetList(queryParams)

  const assets = data?.data ?? EMPTY_ASSETS
  const total = data?.total ?? 0

  const riskStats = useMemo(
    () =>
      assets.reduce(
        (acc, asset) => {
          acc[asset.risk_level] = (acc[asset.risk_level] || 0) + 1
          return acc
        },
        {} as Record<string, number>,
      ),
    [assets],
  )

  const expandedRow = (record: Asset) => (
    <Descriptions size="small" column={3} bordered>
      <Descriptions.Item label="Agent ID">{record.agent_id || '-'}</Descriptions.Item>
      <Descriptions.Item label="首次发现">
        {record.first_seen_at ? new Date(record.first_seen_at).toLocaleString('zh-CN') : '-'}
      </Descriptions.Item>
      <Descriptions.Item label="最后发现">
        {record.last_seen_at ? new Date(record.last_seen_at).toLocaleString('zh-CN') : '-'}
      </Descriptions.Item>
      <Descriptions.Item label="国家/地区">{record.country || '-'}</Descriptions.Item>
      <Descriptions.Item label="省份">{record.province || '-'}</Descriptions.Item>
      <Descriptions.Item label="城市">{record.city || '-'}</Descriptions.Item>
      <Descriptions.Item label="ISP">{record.isp || '-'}</Descriptions.Item>
      <Descriptions.Item label="ASN">{record.asn || '-'}</Descriptions.Item>
      <Descriptions.Item label="附加信息">
        {record.metadata
          ? 'raw' in record.metadata
            ? String(record.metadata.raw)
            : JSON.stringify(record.metadata, null, 2)
          : '-'}
      </Descriptions.Item>
    </Descriptions>
  )

  const columns: ColumnsType<Asset> = [
    {
      title: 'IP',
      dataIndex: 'ip',
      key: 'ip',
      width: 140,
      render: (value: string) => <Typography.Text copyable={{ text: value }}>{value}</Typography.Text>,
    },
    { title: '端口', dataIndex: 'port', key: 'port', width: 70, align: 'right' },
    {
      title: 'Agent类型',
      dataIndex: 'agent_type',
      key: 'agent_type',
      width: 120,
      render: (value: string) => <Typography.Text style={{ color: '#1677ff' }}>{value}</Typography.Text>,
    },
    { title: '版本', dataIndex: 'version', key: 'version', width: 120 },
    {
      title: '认证模式',
      dataIndex: 'auth_mode',
      key: 'auth_mode',
      width: 120,
      render: (value: string) => <AuthTag mode={value} />,
    },
    {
      title: '风险等级',
      dataIndex: 'risk_level',
      key: 'risk_level',
      width: 100,
      render: (value: string) => <RiskTag level={value} />,
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      key: 'confidence',
      width: 90,
      align: 'right',
      render: (value: number) => (
        <Typography.Text style={{ color: confidenceColor(value) }}>{Math.round(value)}%</Typography.Text>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 80,
      render: (value: string) => (
        <Badge status={value === 'active' ? 'success' : 'default'} text={value === 'active' ? '在线' : '离线'} />
      ),
    },
  ]

  const hasFilters = Boolean(params.ip || params.agent_type || params.risk_level)

  return (
    <div>
      <Typography.Title level={4}>资产管理</Typography.Title>

      <StatCards
        loading={isLoading}
        items={[
          { title: '总资产', value: total, prefix: <CloudServerOutlined /> },
          {
            title: '严重风险',
            value: riskStats.critical || 0,
            valueStyle: { color: '#f5222d' },
            prefix: <WarningOutlined />,
          },
          { title: '高危', value: riskStats.high || 0, valueStyle: { color: '#fa8c16' } },
          {
            title: '安全',
            value: (riskStats.low || 0) + (riskStats.info || 0),
            valueStyle: { color: '#52c41a' },
            prefix: <SafetyCertificateOutlined />,
          },
        ]}
      />

      <Space style={{ marginTop: 16, marginBottom: 16 }} wrap>
        <Input.Search
          placeholder="搜索IP"
          allowClear
          style={{ width: 220 }}
          prefix={<SearchOutlined />}
          value={searchIP}
          onChange={(event) => setSearchIP(event.target.value)}
          onSearch={(value) => setParams({ ip: value.trim(), page: 1 }, { replace: false })}
        />
        <Select
          placeholder="Agent类型"
          allowClear
          style={{ width: 160 }}
          value={params.agent_type || undefined}
          options={[
            { label: 'OpenClaw', value: 'openclaw' },
            { label: 'Unknown', value: 'unknown' },
          ]}
          onChange={(value) => setParams({ agent_type: value ?? '', page: 1 }, { replace: false })}
        />
        <Select
          placeholder="风险等级"
          allowClear
          style={{ width: 140 }}
          value={params.risk_level || undefined}
          options={getRiskOptions()}
          onChange={(value) => setParams({ risk_level: value ?? '', page: 1 }, { replace: false })}
        />
        {hasFilters && (
          <Button onClick={() => resetParams({}, { replace: false })}>
            清空筛选
          </Button>
        )}
      </Space>

      <Table
        columns={columns}
        dataSource={assets}
        rowKey="id"
        loading={isLoading}
        expandable={{ expandedRowRender: expandedRow }}
        pagination={{
          current: params.page,
          pageSize: params.limit,
          total,
          showSizeChanger: true,
          showTotal: (value) => `共 ${value} 条`,
          onChange: (page, pageSize) => setParams({ page, limit: pageSize }, { replace: false }),
        }}
        size="middle"
        scroll={{ x: 1200 }}
      />
    </div>
  )
}
