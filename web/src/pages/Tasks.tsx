import { useState } from 'react'
import { Link } from 'react-router-dom'
import type { ColumnsType } from 'antd/es/table'
import type { UploadProps } from 'antd'
import {
  Table,
  Button,
  Modal,
  Form,
  Input,
  Select,
  Space,
  Tag,
  Typography,
  message,
  Popconfirm,
  InputNumber,
  Switch,
  Progress,
  Tooltip,
  Upload,
} from 'antd'
import {
  PlusOutlined,
  PlayCircleOutlined,
  DeleteOutlined,
  DownloadOutlined,
  StopOutlined,
  EyeOutlined,
  UploadOutlined,
} from '@ant-design/icons'
import { useTaskList, useCreateTask, useStartTask, useStopTask, useDeleteTask } from '@/api/tasks'
import { exportExcel } from '@/api/reports'
import { useImportTargets } from '@/api/targets'
import { TASK_STATUS_CONFIG } from '@/constants'
import { useURLQueryState } from '@/hooks/useURLQueryState'
import StatusBadge from '@/components/StatusBadge'
import type { Task, CreateTaskRequest, TaskStatus, TaskType, TaskListParams } from '@/types'

type TaskQueryState = {
  page: number
  limit: number
  status: string
}

const TASK_QUERY_DEFAULTS: TaskQueryState = {
  page: 1,
  limit: 20,
  status: '',
}

function canDownloadReport(status: TaskStatus) {
  return status === 'completed' || status === 'cancelled'
}

export default function Tasks() {
  const [modalOpen, setModalOpen] = useState(false)
  const [taskType, setTaskType] = useState<TaskType>('instant')
  const [form] = Form.useForm<CreateTaskRequest>()
  const { params, setParams, resetParams } = useURLQueryState(TASK_QUERY_DEFAULTS)

  const queryParams: TaskListParams = {
    page: params.page,
    limit: params.limit,
    status: params.status ? (params.status as TaskStatus) : undefined,
  }

  const { data, isLoading } = useTaskList(queryParams)
  const createTask = useCreateTask()
  const startTask = useStartTask()
  const stopTask = useStopTask()
  const deleteTask = useDeleteTask()
  const importTargets = useImportTargets()

  const tasks = data?.data ?? []
  const total = data?.total ?? 0

  const handleCreate = async () => {
    try {
      const values = await form.validateFields()
      await createTask.mutateAsync(values)
      message.success(values.type === 'scheduled' ? '定时任务已创建' : '任务已创建并开始执行')
      setModalOpen(false)
      form.resetFields()
      setTaskType('instant')
      importTargets.reset()
    } catch (e: unknown) {
      if (e instanceof Error && e.message) message.error(e.message)
    }
  }

  const applyImportedTargets = (targets: string, count: number) => {
    form.setFieldValue('targets', targets)
    message.success(`已导入 ${count} 个目标`)
  }

  const handleImportTargets = async (file: File) => {
    try {
      const result = await importTargets.mutateAsync(file)
      const currentTargets = String(form.getFieldValue('targets') || '').trim()

      if (currentTargets) {
        Modal.confirm({
          title: '覆盖当前扫描目标？',
          content: `已从文件解析 ${result.count} 个目标，导入后将覆盖当前文本框内容。`,
          okText: '覆盖',
          cancelText: '取消',
          onOk: () => applyImportedTargets(result.targets, result.count),
        })
      } else {
        applyImportedTargets(result.targets, result.count)
      }
    } catch (e: unknown) {
      if (e instanceof Error && e.message) {
        message.error(e.message)
      }
    }

    return false
  }

  const uploadProps: UploadProps = {
    accept: '.txt,.csv,text/plain,text/csv',
    showUploadList: false,
    beforeUpload: (file) => {
      void handleImportTargets(file)
      return false
    },
  }

  const columns: ColumnsType<Task> = [
    {
      title: '任务名',
      dataIndex: 'name',
      key: 'name',
      width: 200,
      render: (value: string, record: Task) => (
        <Link to={`/tasks/${record.id}`}>
          <Typography.Text strong style={{ color: '#1677ff' }}>
            {value}
          </Typography.Text>
        </Link>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (status: TaskStatus) => <StatusBadge status={status} />,
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      width: 90,
      render: (value: string, record: Task) =>
        value === 'scheduled' ? (
          <Tooltip title={record.cron_expr}>
            <Tag color="blue">定时</Tag>
          </Tooltip>
        ) : (
          <Tag>即时</Tag>
        ),
    },
    {
      title: '深度',
      dataIndex: 'scan_depth',
      key: 'scan_depth',
      width: 70,
      render: (value: string) => <Tag>{value?.toUpperCase()}</Tag>,
    },
    { title: '目标', dataIndex: 'total_targets', key: 'total_targets', width: 70, align: 'right' },
    {
      title: '端口',
      dataIndex: 'open_ports',
      key: 'open_ports',
      width: 70,
      align: 'right',
      render: (value: number) => (value > 0 ? <Typography.Text type="success">{value}</Typography.Text> : '-'),
    },
    {
      title: 'Agent',
      dataIndex: 'found_agents',
      key: 'found_agents',
      width: 70,
      align: 'right',
      render: (value: number) => (value > 0 ? <Typography.Text style={{ color: '#1677ff' }}>{value}</Typography.Text> : '-'),
    },
    {
      title: '漏洞',
      dataIndex: 'found_vulns',
      key: 'found_vulns',
      width: 70,
      align: 'right',
      render: (value: number) => (value > 0 ? <Typography.Text type="danger">{value}</Typography.Text> : '-'),
    },
    {
      title: '进度',
      dataIndex: 'progress_percent',
      key: 'progress',
      width: 160,
      render: (value: number, record: Task) =>
        record.status === 'running' ? (
          <Progress percent={Math.round(value)} size="small" status="active" />
        ) : record.status === 'completed' ? (
          <Progress percent={100} size="small" />
        ) : record.status === 'failed' ? (
          <Progress percent={Math.round(value)} size="small" status="exception" />
        ) : record.status === 'cancelled' ? (
          <Tooltip title="已取消">
            <Progress percent={Math.round(value)} size="small" status="exception" strokeColor="#999" />
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 160,
      render: (value: string) => (value ? new Date(value).toLocaleString('zh-CN') : '-'),
    },
    {
      title: '操作',
      key: 'actions',
      width: 280,
      fixed: 'right',
      render: (_: unknown, record: Task) => (
        <Space size="small">
          <Tooltip title="查看详情">
            <Link to={`/tasks/${record.id}`}>
              <Button size="small" icon={<EyeOutlined />} />
            </Link>
          </Tooltip>
          {record.status === 'pending' && (
            <Tooltip title="启动">
              <Button
                size="small"
                type="primary"
                ghost
                icon={<PlayCircleOutlined />}
                onClick={() => startTask.mutate(record.id)}
              />
            </Tooltip>
          )}
          {record.status === 'running' && (
            <Tooltip title="停止">
              <Button size="small" danger icon={<StopOutlined />} onClick={() => stopTask.mutate(record.id)} />
            </Tooltip>
          )}
          {canDownloadReport(record.status) && (
            <Button size="small" icon={<DownloadOutlined />} onClick={() => exportExcel(record.id)}>
              下载报告
            </Button>
          )}
          <Popconfirm title="确认删除该任务?" onConfirm={() => deleteTask.mutate(record.id)}>
            <Button size="small" icon={<DeleteOutlined />} danger />
          </Popconfirm>
        </Space>
      ),
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Typography.Title level={4} style={{ margin: 0 }}>
          扫描任务
        </Typography.Title>
        <Space>
          <Typography.Text type="secondary">{total} 个任务</Typography.Text>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>
            新建任务
          </Button>
        </Space>
      </div>

      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="任务状态"
          allowClear
          style={{ width: 180 }}
          value={params.status || undefined}
          options={Object.entries(TASK_STATUS_CONFIG).map(([value, config]) => ({
            label: config.label,
            value,
          }))}
          onChange={(value) => setParams({ status: value ?? '', page: 1 }, { replace: false })}
        />
        {params.status && (
          <Button onClick={() => resetParams({}, { replace: false })}>
            清空筛选
          </Button>
        )}
      </Space>

      <Table
        columns={columns}
        dataSource={tasks}
        rowKey="id"
        loading={isLoading}
        pagination={{
          current: params.page,
          pageSize: params.limit,
          total,
          showSizeChanger: true,
          showTotal: (value) => `共 ${value} 条`,
          onChange: (page, pageSize) => setParams({ page, limit: pageSize }, { replace: false }),
        }}
        size="middle"
        scroll={{ x: 1360 }}
      />

      <Modal
        title="新建扫描任务"
        open={modalOpen}
        onOk={handleCreate}
        onCancel={() => setModalOpen(false)}
        width={640}
        okText={taskType === 'scheduled' ? '创建任务' : '创建并执行'}
        confirmLoading={createTask.isPending}
        destroyOnHidden
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{ scan_depth: 'l3', concurrency: 100, timeout: 3, enable_mdns: true, type: 'instant' }}
        >
          <Form.Item name="name" label="任务名称" rules={[{ required: true, message: '请输入任务名称' }]}>
            <Input placeholder="如: 内网Agent排查-2026Q1" />
          </Form.Item>
          <Space size="large" wrap>
            <Form.Item name="type" label="任务类型">
              <Select
                style={{ width: 140 }}
                onChange={(value: TaskType) => setTaskType(value)}
                options={[
                  { label: '即时执行', value: 'instant' },
                  { label: '定时执行', value: 'scheduled' },
                ]}
              />
            </Form.Item>
            {taskType === 'scheduled' && (
              <Form.Item
                name="cron_expr"
                label="Cron 表达式"
                rules={[{ required: true, message: '请输入 Cron 表达式' }]}
                extra="标准 5 字段: 分 时 日 月 周 (如 0 */6 * * *)"
              >
                <Input placeholder="0 */6 * * *" style={{ width: 200 }} />
              </Form.Item>
            )}
          </Space>
          <Form.Item
            name="targets"
            label={
              <Space>
                <span>扫描目标</span>
                <Upload {...uploadProps}>
                  <Button size="small" icon={<UploadOutlined />} loading={importTargets.isPending}>
                    导入文件
                  </Button>
                </Upload>
              </Space>
            }
            rules={[{ required: true, message: '请输入扫描目标' }]}
            extra={
              importTargets.data
                ? `最近一次导入解析出 ${importTargets.data.count} 个目标。支持: 单IP、CIDR、IP范围、逗号分隔多段。`
                : '支持: 单IP、CIDR (192.168.1.0/24)、范围 (10.0.0.1-10.0.0.255)、逗号分隔多段。'
            }
          >
            <Input.TextArea rows={3} placeholder="192.168.1.0/24, 10.0.0.1" />
          </Form.Item>
          <Form.Item name="description" label="任务描述">
            <Input.TextArea rows={2} placeholder="可选描述信息" />
          </Form.Item>
          <Form.Item name="ports" label="端口" extra="留空使用默认端口: 18789,18792,3000,8080,8888">
            <Input placeholder="18789,18792,3000,8080,8888" />
          </Form.Item>
          <Space size="large" wrap>
            <Form.Item name="scan_depth" label="扫描深度">
              <Select
                style={{ width: 140 }}
                options={[
                  { label: 'L1 端口扫描', value: 'l1' },
                  { label: 'L2 指纹识别', value: 'l2' },
                  { label: 'L3 漏洞验证', value: 'l3' },
                ]}
              />
            </Form.Item>
            <Form.Item name="concurrency" label="并发数">
              <InputNumber min={1} max={10000} style={{ width: 100 }} />
            </Form.Item>
            <Form.Item name="timeout" label="超时(秒)">
              <InputNumber min={1} max={60} style={{ width: 100 }} />
            </Form.Item>
            <Form.Item name="enable_mdns" label="mDNS发现" valuePropName="checked">
              <Switch />
            </Form.Item>
          </Space>
        </Form>
      </Modal>
    </div>
  )
}
