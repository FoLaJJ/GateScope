import { useEffect, useMemo, useState } from 'react'
import type { ColumnsType } from 'antd/es/table'
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Input,
  Select,
  Space,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import { useVulnList } from '@/api/vulns'
import { useRuleCatalog, useRuleCatalogEntries } from '@/api/rules'
import RiskTag from '@/components/RiskTag'
import AuthTag from '@/components/AuthTag'
import { cvssColor, getRiskOptions } from '@/constants'
import { CHECK_TYPE_LABELS, getCheckTypeOptions } from '@/constants/check'
import { useURLQueryState } from '@/hooks/useURLQueryState'
import { displayCVSS, displayTimeUnknown, displayUnknown, toFiniteNumber } from '@/utils/display'
import { describeIdentifierState, extractVersionContext, getPreferredDescription, listVulnerabilityIdentifiers } from '@/utils/vuln'
import type { RuleCatalogEntry, Vulnerability, VulnListParams } from '@/types'

type VulnerabilityQueryState = {
  view: 'catalog' | 'findings'
  page: number
  limit: number
  identifier: string
  identifier_type: string
  severity: string
  check_type: string
}

const VULN_QUERY_DEFAULTS: VulnerabilityQueryState = {
  view: 'catalog',
  page: 1,
  limit: 20,
  identifier: '',
  identifier_type: '',
  severity: '',
  check_type: '',
}

const EMPTY_VULNS: Vulnerability[] = []
const EMPTY_RULES: RuleCatalogEntry[] = []

export default function Vulnerabilities() {
  const { params, setParams, resetParams } = useURLQueryState(VULN_QUERY_DEFAULTS)
  const [searchIdentifier, setSearchIdentifier] = useState(params.identifier)

  useEffect(() => {
    setSearchIdentifier(params.identifier)
  }, [params.identifier])

  const findingQueryParams: VulnListParams = {
    page: params.page,
    limit: params.limit,
    identifier: params.identifier || undefined,
    identifier_type: params.identifier_type ? (params.identifier_type as 'cve' | 'cnnvd') : undefined,
    severity: params.severity ? (params.severity as Vulnerability['severity']) : undefined,
    check_type: params.check_type ? (params.check_type as Vulnerability['check_type']) : undefined,
  }

  const { data: findingsData, isLoading: findingsLoading } = useVulnList(findingQueryParams)
  const { data: ruleCatalog } = useRuleCatalog()
  const { data: catalogData, isLoading: catalogLoading } = useRuleCatalogEntries()

  const findings = findingsData?.data ?? EMPTY_VULNS
  const findingsTotal = findingsData?.total ?? 0
  const catalogRules = catalogData?.data ?? EMPTY_RULES

  const filteredCatalog = useMemo(() => {
    return catalogRules.filter((rule) => {
      if (params.severity && rule.severity !== params.severity) {
        return false
      }

      const keyword = params.identifier.trim().toLowerCase()
      if (!keyword) {
        return true
      }

      if (params.identifier_type === 'cve') {
        return rule.cve_id.toLowerCase().includes(keyword)
      }
      if (params.identifier_type === 'cnnvd') {
        return (rule.cnnvd_id || '').toLowerCase().includes(keyword)
      }

      return [rule.cve_id, rule.cnnvd_id || '', rule.title, rule.description_zh || '', rule.description || '']
        .join(' ')
        .toLowerCase()
        .includes(keyword)
    })
  }, [catalogRules, params.identifier, params.identifier_type, params.severity])

  const paginatedCatalog = useMemo(() => {
    const start = (params.page - 1) * params.limit
    return filteredCatalog.slice(start, start + params.limit)
  }, [filteredCatalog, params.page, params.limit])

  const currentView = params.view || 'catalog'
  const visibleRows = currentView === 'catalog' ? paginatedCatalog : findings
  const visibleTotal = currentView === 'catalog' ? filteredCatalog.length : findingsTotal
  const currentLoading = currentView === 'catalog' ? catalogLoading : findingsLoading
  const ruleIssues = Array.isArray(ruleCatalog?.issues) ? ruleCatalog.issues : []

  const sevStats = useMemo(
    () =>
      visibleRows.reduce(
        (acc, row) => {
          acc[row.severity] = (acc[row.severity] || 0) + 1
          return acc
        },
        {} as Record<string, number>,
      ),
    [visibleRows],
  )

  const renderIdentifiers = (record: RuleCatalogEntry | Vulnerability) => {
    const identifiers = listVulnerabilityIdentifiers(record)
    if (identifiers.length === 0) {
      if ('check_type' in record) {
        const state = describeIdentifierState(record)
        return state ? <Tag>{state}</Tag> : '-'
      }
      return '-'
    }

    return (
      <Space size={[4, 4]} wrap>
        {identifiers.map((identifier) => (
          <Tag color="geekblue" key={identifier.key}>
            <Typography.Link className="identifier-link" href={identifier.href} target="_blank" rel="noreferrer">
              {identifier.label}
            </Typography.Link>
          </Tag>
        ))}
      </Space>
    )
  }

  const renderCatalogExpandedRow = (record: RuleCatalogEntry) => (
    <Descriptions size="small" column={2} bordered>
      <Descriptions.Item label="漏洞编号" span={2}>
        {renderIdentifiers(record)}
      </Descriptions.Item>
      <Descriptions.Item label="受影响版本">{record.affected_before ? `< ${record.affected_before}` : '未查明'}</Descriptions.Item>
      <Descriptions.Item label="本地PoC规则">{record.has_local_poc ? '是' : '否'}</Descriptions.Item>
      <Descriptions.Item label="完整描述" span={2}>
        <Space direction="vertical" size={4} style={{ width: '100%' }}>
          <div>
            <Typography.Text strong>中文：</Typography.Text>
            <Typography.Text>{displayUnknown(record.description_zh, '未提供中文描述')}</Typography.Text>
          </div>
          <div>
            <Typography.Text strong>English:</Typography.Text>
            <Typography.Text>{displayUnknown(record.description, 'No English description available')}</Typography.Text>
          </div>
        </Space>
      </Descriptions.Item>
      <Descriptions.Item label="修复建议" span={2}>
        <Typography.Text type="success">{displayUnknown(record.remediation, '未提供修复建议')}</Typography.Text>
      </Descriptions.Item>
    </Descriptions>
  )

  const renderFindingExpandedRow = (record: Vulnerability) => {
    const versionContext = extractVersionContext(record)
    return (
      <Descriptions size="small" column={2} bordered>
        <Descriptions.Item label="关联资产" span={2}>
          {displayUnknown(record.asset_label || record.asset_id, '未关联到资产')}
        </Descriptions.Item>
        <Descriptions.Item label="Agent类型">{displayUnknown(record.agent_type, '未识别')}</Descriptions.Item>
        <Descriptions.Item label="资产版本">{displayUnknown(record.asset_version, '未查明')}</Descriptions.Item>
        <Descriptions.Item label="漏洞编号" span={2}>
          {renderIdentifiers(record)}
        </Descriptions.Item>
        <Descriptions.Item label="认证模式">
          <AuthTag mode={record.auth_mode || 'unknown'} />
        </Descriptions.Item>
        <Descriptions.Item label="资产风险">
          {record.risk_level ? <RiskTag level={record.risk_level} /> : '未查明'}
        </Descriptions.Item>
        <Descriptions.Item label="当前版本">
          {displayUnknown(versionContext.currentVersion || record.asset_version, '未查明')}
        </Descriptions.Item>
        <Descriptions.Item label="修复版本">{displayUnknown(versionContext.fixedVersion, '未提供')}</Descriptions.Item>
        <Descriptions.Item label="本地PoC规则">{versionContext.hasLocalPoCRule ? '是' : '否'}</Descriptions.Item>
        <Descriptions.Item label="检测时间">
          {displayTimeUnknown(record.detected_at)}
        </Descriptions.Item>
        <Descriptions.Item label="完整描述" span={2}>
          <Space direction="vertical" size={4} style={{ width: '100%' }}>
            <div>
              <Typography.Text strong>中文：</Typography.Text>
              <Typography.Text>{displayUnknown(record.description_zh, '未提供中文描述')}</Typography.Text>
            </div>
            <div>
              <Typography.Text strong>English:</Typography.Text>
              <Typography.Text>{displayUnknown(record.description, 'No English description available')}</Typography.Text>
            </div>
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label="修复建议" span={2}>
          <Typography.Text type="success">{displayUnknown(record.remediation, '未提供修复建议')}</Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label="证据" span={2}>
          <Typography.Paragraph code style={{ marginBottom: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }} copyable>
            {displayUnknown(record.evidence, '未采集到证据')}
          </Typography.Paragraph>
        </Descriptions.Item>
      </Descriptions>
    )
  }

  const catalogColumns: ColumnsType<RuleCatalogEntry> = [
    {
      title: '漏洞编号',
      key: 'identifier',
      width: 260,
      render: (_: unknown, record: RuleCatalogEntry) => renderIdentifiers(record),
    },
    {
      title: '标题',
      dataIndex: 'title',
      key: 'title',
      width: 360,
      ellipsis: true,
      render: (value: string, record: RuleCatalogEntry) => (
        <Tooltip title={record.description_zh || record.description || value}>
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
      render: (value: unknown) => (
        <Typography.Text style={{ color: cvssColor(toFiniteNumber(value) ?? 0), fontWeight: 'bold' }}>{displayCVSS(value)}</Typography.Text>
      ),
    },
    {
      title: '受影响版本',
      dataIndex: 'affected_before',
      key: 'affected_before',
      width: 140,
      render: (value?: string) => (value ? `< ${value}` : '未查明'),
    },
    {
      title: '本地PoC',
      dataIndex: 'has_local_poc',
      key: 'has_local_poc',
      width: 100,
      render: (value: boolean) => <Tag color={value ? 'red' : 'default'}>{value ? '优先验证' : '无'}</Tag>,
    },
    {
      title: '修复建议',
      dataIndex: 'remediation',
      key: 'remediation',
      width: 240,
      ellipsis: true,
      render: (value?: string) => <Typography.Text type="success">{displayUnknown(value, '未提供修复建议')}</Typography.Text>,
    },
  ]

  const findingColumns: ColumnsType<Vulnerability> = [
    {
      title: 'IP',
      dataIndex: 'asset_ip',
      key: 'asset_ip',
      width: 150,
      render: (value: string | undefined) => displayUnknown(value, '检测不到'),
    },
    {
      title: '端口',
      dataIndex: 'asset_port',
      key: 'asset_port',
      width: 80,
      render: (value: number | undefined) => (typeof value === 'number' ? value : '检测不到'),
    },
    {
      title: 'Agent',
      dataIndex: 'agent_type',
      key: 'agent_type',
      width: 110,
      render: (value: string | undefined) => <Tag color={value ? 'blue' : 'default'}>{displayUnknown(value, '未识别')}</Tag>,
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
      width: 320,
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
      render: (value: unknown) => (
        <Typography.Text style={{ color: cvssColor(toFiniteNumber(value) ?? 0), fontWeight: 'bold' }}>{displayCVSS(value)}</Typography.Text>
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
      render: (value: string) => <Typography.Text type="success">{displayUnknown(value, '未提供修复建议')}</Typography.Text>,
    },
  ]

  const identifierPlaceholder =
    params.identifier_type === 'cve'
      ? '搜索 CVE 编号'
      : params.identifier_type === 'cnnvd'
        ? '搜索 CNNVD 编号'
        : currentView === 'catalog'
          ? '搜索标题或漏洞编号'
          : '搜索漏洞编号'

  const hasFilters = Boolean(params.identifier || params.identifier_type || params.severity || params.check_type)
  const mappingStatusText =
    ruleCatalog?.cnnvd_count && ruleCatalog.cnnvd_count > 0
      ? `当前有效 CNNVD 对应关系 ${ruleCatalog.cnnvd_count} 条。`
      : '当前还没有可用的 CNNVD 对应关系。'

  return (
    <div>
      <section className="page-hero">
        <Typography.Text className="page-hero-subtitle">Catalog and Findings</Typography.Text>
        <Typography.Title level={2} className="page-hero-title">
          漏洞中心
        </Typography.Title>
        <Typography.Paragraph className="page-hero-subtitle" style={{ marginBottom: 0 }}>
          当前漏洞库展示 YAML 规则库里的 OpenClaw 全量 CVE；已扫描发现展示任务实际命中的结果。无编号项只会出现在“已扫描发现”里，表示认证/技能等内置暴露检查，不计入 CVE 规则库。
        </Typography.Paragraph>
        <div className="hero-chip-row">
          <div className="hero-chip">
            <span>当前漏洞库</span>
            <strong>{catalogRules.length || 0}</strong>
          </div>
          <div className="hero-chip">
            <span>已扫描发现</span>
            <strong>{findingsTotal}</strong>
          </div>
          <div className="hero-chip">
            <span>本地PoC</span>
            <strong>{ruleCatalog?.poc_count || 0}</strong>
          </div>
        </div>
      </section>

      {ruleCatalog && (
        <Alert
          style={{ marginBottom: 16 }}
          type={ruleCatalog.consistent ? 'info' : 'warning'}
          showIcon
          message={`规则库更新时间：${ruleCatalog.updated_at || '未标注'}，上游检索截止：${ruleCatalog.source_cutoff || '未标注'}`}
          description={`当前规则库共 ${ruleCatalog.rule_count} 条，其中 CVE ${ruleCatalog.cve_count} 条、CNNVD 映射 ${ruleCatalog.cnnvd_count} 条、PoC ${ruleCatalog.poc_count} 条。${
            ruleCatalog.consistent ? '当前映射校验通过。' : `当前存在 ${ruleIssues.length} 条映射告警。`
          } ${mappingStatusText} 已扫描发现页仍会显示无外部编号的内置暴露检查结果。${ruleCatalog.notes ? ` ${ruleCatalog.notes}` : ''}`}
        />
      )}

      <div className="metric-strip">
        <div className="metric-strip-card">
          <span className="label">{currentView === 'catalog' ? '当前筛选结果' : '已扫描结果'}</span>
          <div className="value">{currentLoading ? '-' : visibleTotal}</div>
        </div>
        <div className="metric-strip-card">
          <span className="label">严重</span>
          <div className="value" style={{ color: 'var(--gs-danger)' }}>
            {currentLoading ? '-' : sevStats.critical || 0}
          </div>
        </div>
        <div className="metric-strip-card">
          <span className="label">高危</span>
          <div className="value" style={{ color: 'var(--gs-accent-strong)' }}>
            {currentLoading ? '-' : sevStats.high || 0}
          </div>
        </div>
        <div className="metric-strip-card">
          <span className="label">中/低危</span>
          <div className="value" style={{ color: 'var(--gs-success)' }}>
            {currentLoading ? '-' : (sevStats.medium || 0) + (sevStats.low || 0) + (sevStats.info || 0)}
          </div>
        </div>
      </div>

      <Tabs
        activeKey={currentView}
        style={{ marginBottom: 16 }}
        onChange={(value) => setParams({ view: value as 'catalog' | 'findings', page: 1 }, { replace: false })}
        items={[
          { key: 'catalog', label: `当前漏洞库 (${catalogRules.length || 0})` },
          { key: 'findings', label: `已扫描发现 (${findingsTotal})` },
        ]}
      />

      <Card className="filters-card">
        <Space wrap>
          <Select
            placeholder="编号类型"
            allowClear
            style={{ width: 140 }}
            value={params.identifier_type || undefined}
            options={[
              { label: 'CVE', value: 'cve' },
              { label: 'CNNVD', value: 'cnnvd' },
            ]}
            onChange={(value) => setParams({ identifier_type: value ?? '', page: 1 }, { replace: false })}
          />
          <Input.Search
            placeholder={identifierPlaceholder}
            allowClear
            style={{ width: 260 }}
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
          {currentView === 'findings' && (
            <Select
              placeholder="判定依据"
              allowClear
              style={{ width: 160 }}
              value={params.check_type || undefined}
              options={getCheckTypeOptions()}
              onChange={(value) => setParams({ check_type: value ?? '', page: 1 }, { replace: false })}
            />
          )}
          {hasFilters && <Button onClick={() => resetParams({ view: currentView }, { replace: false })}>清空筛选</Button>}
        </Space>
      </Card>

      {currentView === 'catalog' ? (
        <Card className="surface-card table-card">
          <Table
            columns={catalogColumns}
            dataSource={paginatedCatalog}
            rowKey="id"
            loading={catalogLoading}
            expandable={{ expandedRowRender: renderCatalogExpandedRow }}
            pagination={{
              current: params.page,
              pageSize: params.limit,
              total: filteredCatalog.length,
              showSizeChanger: true,
              showTotal: (value) => `共 ${value} 条`,
              onChange: (page, pageSize) => setParams({ page, limit: pageSize }, { replace: false }),
            }}
            size="middle"
            scroll={{ x: 1450 }}
          />
        </Card>
      ) : (
        <Card className="surface-card table-card">
          <Table
            columns={findingColumns}
            dataSource={findings}
            rowKey="id"
            loading={findingsLoading}
            expandable={{ expandedRowRender: renderFindingExpandedRow }}
            pagination={{
              current: params.page,
              pageSize: params.limit,
              total: findingsTotal,
              showSizeChanger: true,
              showTotal: (value) => `共 ${value} 条`,
              onChange: (page, pageSize) => setParams({ page, limit: pageSize }, { replace: false }),
            }}
            size="middle"
            scroll={{ x: 1600 }}
          />
        </Card>
      )}
    </div>
  )
}
