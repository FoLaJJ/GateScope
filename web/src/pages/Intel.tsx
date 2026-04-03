import { useEffect, useRef } from 'react'
import type { ColumnsType } from 'antd/es/table'
import { useLocation, useNavigate } from 'react-router-dom'
import { Button, Card, Form, Input, InputNumber, Space, Table, Tag, Typography, message } from 'antd'
import { CloudUploadOutlined, SearchOutlined } from '@ant-design/icons'
import { useFOFAImport, useFOFASearch } from '@/api/intel'
import { useURLQueryState } from '@/hooks/useURLQueryState'
import type { FOFASearchRequest, IntelResult } from '@/types'

type IntelQueryState = {
  query: string
  limit: number
}

const INTEL_QUERY_DEFAULTS: IntelQueryState = {
  query: '',
  limit: 100,
}

export default function Intel() {
  const [form] = Form.useForm<{ query: string; limit: number; taskName: string }>()
  const { params, setParams } = useURLQueryState(INTEL_QUERY_DEFAULTS)
  const location = useLocation()
  const navigate = useNavigate()
  const skipNextAutoSearchRef = useRef(false)
  const lastAutoSearchKeyRef = useRef('')

  const { mutate: triggerSearch, ...searchMutation } = useFOFASearch()
  const importMutation = useFOFAImport()

  useEffect(() => {
    form.setFieldsValue({
      query: params.query,
      limit: params.limit,
    })
  }, [form, params.limit, params.query])

  useEffect(() => {
    const search = new URLSearchParams(location.search)
    const shouldAutoSearch = search.has('query') || search.has('limit')
    const searchKey = `${params.query}::${params.limit}`

    if (!shouldAutoSearch) {
      lastAutoSearchKeyRef.current = ''
      return
    }
    if (skipNextAutoSearchRef.current) {
      skipNextAutoSearchRef.current = false
      lastAutoSearchKeyRef.current = searchKey
      return
    }
    if (lastAutoSearchKeyRef.current === searchKey) {
      return
    }

    lastAutoSearchKeyRef.current = searchKey
    triggerSearch({
      query: params.query,
      limit: params.limit,
    })
  }, [location.search, params.limit, params.query, triggerSearch])

  const handleSearch = async () => {
    try {
      const values = await form.validateFields()
      const payload: FOFASearchRequest = {
        query: values.query?.trim(),
        limit: values.limit,
      }

      skipNextAutoSearchRef.current = true
      lastAutoSearchKeyRef.current = `${payload.query || ''}::${payload.limit}`
      setParams(payload, { replace: false })
      triggerSearch(payload)
    } catch (e: unknown) {
      if (e instanceof Error && e.message) {
        message.error(e.message)
      }
    }
  }

  const handleImport = async () => {
    try {
      const values = await form.validateFields()
      const result = await importMutation.mutateAsync({
        query: values.query?.trim(),
        limit: values.limit,
        task_name: values.taskName?.trim() || undefined,
      })

      message.success(result.message)
      navigate(`/tasks/${result.task.id}`)
    } catch (e: unknown) {
      if (e instanceof Error && e.message) {
        message.error(e.message)
      }
    }
  }

  const results = searchMutation.data?.data ?? []
  const total = searchMutation.data?.total ?? 0

  const columns: ColumnsType<IntelResult> = [
    {
      title: 'IP',
      dataIndex: 'ip',
      key: 'ip',
      width: 140,
      render: (value: string) => <Typography.Text copyable={{ text: value }}>{value}</Typography.Text>,
    },
    { title: '端口', dataIndex: 'port', key: 'port', width: 80, align: 'right' },
    {
      title: '协议',
      dataIndex: 'protocol',
      key: 'protocol',
      width: 100,
      render: (value: string) => <Tag color="geekblue">{value || '-'}</Tag>,
    },
    {
      title: 'Host',
      dataIndex: 'host',
      key: 'host',
      width: 220,
      ellipsis: true,
      render: (value: string) => value || '-',
    },
    {
      title: '标题',
      dataIndex: 'title',
      key: 'title',
      width: 240,
      ellipsis: true,
      render: (value: string) => value || '-',
    },
    {
      title: '位置',
      key: 'location',
      width: 180,
      render: (_value, record) => [record.country, record.city].filter(Boolean).join(' / ') || '-',
    },
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      width: 100,
      render: (value: string) => <Tag>{value || 'fofa'}</Tag>,
    },
    {
      title: 'Banner',
      dataIndex: 'banner',
      key: 'banner',
      ellipsis: true,
      render: (value: string) => value || '-',
    },
  ]

  return (
    <div>
      <Typography.Title level={4}>情报中心</Typography.Title>

      <Card style={{ marginBottom: 16 }}>
        <Form
          form={form}
          layout="vertical"
          initialValues={{
            query: params.query,
            limit: params.limit,
            taskName: '',
          }}
        >
          <Form.Item
            name="query"
            label="FOFA 查询语句"
            extra="留空会使用后端默认 OpenClaw 查询模板。"
          >
            <Input.TextArea rows={3} placeholder='例如: title="OpenClaw" && country="CN"' />
          </Form.Item>
          <Space size="large" wrap align="start">
            <Form.Item
              name="limit"
              label="查询数量"
              rules={[{ required: true, message: '请输入查询数量' }]}
            >
              <InputNumber min={1} max={10000} style={{ width: 160 }} />
            </Form.Item>
            <Form.Item name="taskName" label="导入后任务名">
              <Input placeholder="留空则自动生成任务名" style={{ width: 280 }} />
            </Form.Item>
          </Space>
          <Space wrap>
            <Button type="primary" icon={<SearchOutlined />} onClick={() => void handleSearch()} loading={searchMutation.isPending}>
              搜索 FOFA
            </Button>
            <Button
              icon={<CloudUploadOutlined />}
              onClick={() => void handleImport()}
              loading={importMutation.isPending}
              disabled={total === 0}
            >
              导入并创建任务
            </Button>
            <Typography.Text type="secondary">
              {searchMutation.isSuccess ? `当前结果 ${total} 条` : '先执行搜索，再导入结果创建扫描任务。'}
            </Typography.Text>
          </Space>
        </Form>
      </Card>

      <Table
        rowKey={(record) => `${record.ip}:${record.port}:${record.protocol}`}
        columns={columns}
        dataSource={results}
        loading={searchMutation.isPending}
        locale={{
          emptyText: searchMutation.isError ? '搜索失败，请检查 FOFA 配置或查询语句。' : '请输入查询条件并执行搜索',
        }}
        pagination={{ pageSize: 20, showSizeChanger: true, showTotal: (value) => `共 ${value} 条结果` }}
        scroll={{ x: 1280 }}
      />
    </div>
  )
}
