import { useEffect, useMemo, useState } from 'react'
import type { ColumnsType } from 'antd/es/table'
import { Table, Typography, Select, Space, Descriptions, Input, Tooltip, Tag, Button, Alert } from 'antd'
import { BugOutlined, WarningOutlined, SafetyCertificateOutlined, SearchOutlined } from '@ant-design/icons'
import { useVulnList } from '@/api/vulns'
import { useRuleCatalog } from '@/api/rules'
import StatCards from '@/components/StatCards'
import RiskTag from '@/components/RiskTag'
import AuthTag from '@/components/AuthTag'
import { cvssColor, getRiskOptions } from '@/constants'
import { CHECK_TYPE_LABELS, getCheckTypeOptions } from '@/constants/check'
import { useURLQueryState } from '@/hooks/useURLQueryState'
import { extractVersionContext, getPreferredDescription, listVulnerabilityIdentifiers } from '@/utils/vuln'
import type { Vulnerability, VulnListParams } from '@/types'

type VulnerabilityQueryState = {
  page: number
  limit: number
  identifier: string
  identifier_type: string
  severity: string
  check_type: string
}

const VULN_QUERY_DEFAULTS: VulnerabilityQueryState = {
  page: 1,
  limit: 20,
  identifier: '',
  identifier_type: '',
  severity: '',
  check_type: '',
}

const EMPTY_VULNS: Vulnerability[] = []

export default function Vulnerabilities() {
  const { params, setParams, resetParams } = useURLQueryState(VULN_QUERY_DEFAULTS)
  const [searchIdentifier, setSearchIdentifier] = useState(params.identifier)

  useEffect(() => {
    setSearchIdentifier(params.identifier)
  }, [params.identifier])

  const queryParams: VulnListParams = {
    page: params.page,
    limit: params.limit,
    identifier: params.identifier || undefined,
    identifier_type: params.identifier_type ? (params.identifier_type as 'cve' | 'cnnvd' | 'ghsa') : undefined,
    severity: params.severity ? (params.severity as Vulnerability['severity']) : undefined,
    check_type: params.check_type ? (params.check_type as Vulnerability['check_type']) : undefined,
  }

  const { data, isLoading } = useVulnList(queryParams)
  const { data: ruleCatalog } = useRuleCatalog()

  const vulns = data?.data ?? EMPTY_VULNS
  const total = data?.total ?? 0

  const sevStats = useMemo(
    () =>
      vulns.reduce(
        (acc, vuln) => {
          acc[vuln.severity] = (acc[vuln.severity] || 0) + 1
          return acc
        },
        {} as Record<string, number>,
      ),
    [vulns],
  )

  const renderIdentifiers = (record: Vulnerability) => {
    const identifiers = listVulnerabilityIdentifiers(record)
    if (identifiers.length === 0) {
      return '-'
    }

    return (
      <Space size={[4, 4]} wrap>
        {identifiers.map((identifier) => (
          <Tag color="geekblue" key={identifier.key}>
            <Typography.Link href={identifier.href} target="_blank">
              {identifier.label}
            </Typography.Link>
          </Tag>
        ))}
      </Space>
    )
  }

  const expandedRow = (record: Vulnerability) => {
    const versionContext = extractVersionContext(record)
    return (
      <Descriptions size="small" column={2} bordered>
        <Descriptions.Item label="关联资产" span={2}>
          {record.asset_label || record.asset_id || '-'}
        </Descriptions.Item>
        <Descriptions.Item label="Agent类型">{record.agent_type || '-'}</Descriptions.Item>
        <Descriptions.Item label="资产版本">{record.asset_version || '-'}</Descriptions.Item>
        <Descriptions.Item label="漏洞编号" span={2}>
          {renderIdentifiers(record)}
        </Descriptions.Item>
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
          <Space direction="vertical" size={4} style={{ width: '100%' }}>
            <div>
              <Typography.Text strong>中文：</Typography.Text>
              <Typography.Text>{record.description_zh || '-'}</Typography.Text>
            </div>
            <div>
              <Typography.Text strong>English:</Typography.Text>
              <Typography.Text>{record.description || '-'}</Typography.Text>
            </div>
          </Space>
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

  const columns: ColumnsType<Vulnerability> = [
    {
      title: 'IP',
      dataIndex: 'asset_ip',
      key: 'asset_ip',
      width: 150,
      render: (value: string | undefined) => value || '-',
    },
    {
      title: '端口',
      dataIndex: 'asset_port',
      key: 'asset_port',
      width: 80,
      render: (value: number | undefined) => value ?? '-',
    },
    {
      title: 'Agent',
      dataIndex: 'agent_type',
      key: 'agent_type',
      width: 110,
      render: (value: string | undefined) => (value ? <Tag color="blue">{value}</Tag> : '-'),
    },
    {
      title: '漏洞编号',
      key: 'identifier',
      width: 260,
      render: (_: unknown, record: Vulnerability) => renderIdentifiers(record),
    },
    {
      title: '标题',
      dataIndex: 'title',
      key: 'title',
      width: 300,
      ellipsis: true,
      render: (value: string, record: Vulnerability) => (
        <Tooltip title={getPreferredDescription(record) || value}>
          <Typography.Text strong>{value}</Typography.Text>
        </Tooltip>
      ),
    },
    {
      title: '严重等级',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      render: (value: string) => <RiskTag level={value} />,
    },
    {
      title: 'CVSS',
      dataIndex: 'cvss',
      key: 'cvss',
      width: 80,
      align: 'right',
      render: (value: number) => (
        <Typography.Text style={{ color: cvssColor(value), fontWeight: 'bold' }}>{value?.toFixed(1)}</Typography.Text>
      ),
    },
    {
      title: '判定依据',
      dataIndex: 'check_type',
      key: 'check_type',
      width: 120,
      render: (value: string) => <Tag color="geekblue">{CHECK_TYPE_LABELS[value] || value}</Tag>,
    },
    {
      title: '修复建议',
      dataIndex: 'remediation',
      key: 'remediation',
      width: 220,
      ellipsis: true,
      render: (value: string) => <Typography.Text type="success">{value || '-'}</Typography.Text>,
    },
  ]

  const identifierPlaceholder =
    params.identifier_type === 'cve'
      ? '搜索CVE编号'
      : params.identifier_type === 'cnnvd'
        ? '搜索CNNVD编号'
        : params.identifier_type === 'ghsa'
          ? '搜索GHSA编号'
          : '搜索漏洞编号'

  const hasFilters = Boolean(params.identifier || params.identifier_type || params.severity || params.check_type)
  const mappingStatusText =
    ruleCatalog?.cnnvd_count && ruleCatalog.cnnvd_count > 0
      ? `已补录 ${ruleCatalog.cnnvd_count} 条 CNNVD 对应关系，可直接按编号类型筛选。`
      : 'CNNVD 映射链路已支持，但当前仍在持续补录可核实的对应关系。'

  return (
    <div>
      <Typography.Title level={4}>漏洞列表</Typography.Title>
      {ruleCatalog && (
        <Alert
          style={{ marginBottom: 16 }}
          type={ruleCatalog.consistent ? 'info' : 'warning'}
          showIcon
          message={`漏洞规则库更新时间：${ruleCatalog.updated_at || '未标注'}，已核对到：${ruleCatalog.source_cutoff || '未标注'}`}
          description={`当前内置 ${ruleCatalog.rule_count} 条版本规则，其中 CVE ${ruleCatalog.cve_count} 条、CNNVD ${ruleCatalog.cnnvd_count} 条、GHSA ${ruleCatalog.ghsa_count} 条，PoC ${ruleCatalog.poc_count} 条。${
            ruleCatalog.consistent ? '当前映射校验通过。' : `当前存在 ${ruleCatalog.issues.length} 条映射告警。`
          } ${mappingStatusText}${ruleCatalog.notes ? ` ${ruleCatalog.notes}` : ''}`}
        />
      )}

      <StatCards
        loading={isLoading}
        items={[
          { title: '总漏洞', value: total, prefix: <BugOutlined /> },
          {
            title: '严重',
            value: sevStats.critical || 0,
            valueStyle: { color: '#f5222d' },
            prefix: <WarningOutlined />,
          },
          { title: '高危', value: sevStats.high || 0, valueStyle: { color: '#fa8c16' } },
          {
            title: '中/低危',
            value: (sevStats.medium || 0) + (sevStats.low || 0) + (sevStats.info || 0),
            valueStyle: { color: '#52c41a' },
            prefix: <SafetyCertificateOutlined />,
          },
        ]}
      />

      <Space style={{ marginTop: 16, marginBottom: 16 }} wrap>
        <Select
          placeholder="编号类型"
          allowClear
          style={{ width: 140 }}
          value={params.identifier_type || undefined}
          options={[
            { label: 'CVE', value: 'cve' },
            { label: 'CNNVD', value: 'cnnvd' },
            { label: 'GHSA', value: 'ghsa' },
          ]}
          onChange={(value) => setParams({ identifier_type: value ?? '', page: 1 }, { replace: false })}
        />
        <Input.Search
          placeholder={identifierPlaceholder}
          allowClear
          style={{ width: 220 }}
          prefix={<SearchOutlined />}
          value={searchIdentifier}
          onChange={(event) => setSearchIdentifier(event.target.value)}
          onSearch={(value) => setParams({ identifier: value.trim(), page: 1 }, { replace: false })}
        />
        <Select
          placeholder="严重等级"
          allowClear
          style={{ width: 140 }}
          value={params.severity || undefined}
          options={getRiskOptions()}
          onChange={(value) => setParams({ severity: value ?? '', page: 1 }, { replace: false })}
        />
        <Select
          placeholder="判定依据"
          allowClear
          style={{ width: 160 }}
          value={params.check_type || undefined}
          options={getCheckTypeOptions()}
          onChange={(value) => setParams({ check_type: value ?? '', page: 1 }, { replace: false })}
        />
        {hasFilters && <Button onClick={() => resetParams({}, { replace: false })}>清空筛选</Button>}
      </Space>

      <Table
        columns={columns}
        dataSource={vulns}
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
        scroll={{ x: 1500 }}
      />
    </div>
  )
}
