import React from 'react'
import { Row, Col, Card, Statistic, Skeleton } from 'antd'

export interface StatItem {
  title: string
  value: number | string
  prefix?: React.ReactNode
  valueStyle?: React.CSSProperties
  suffix?: React.ReactNode
}

interface Props {
  items: StatItem[]
  loading?: boolean
  colSpan?: number
  gutter?: number
}

export default function StatCards({ items, loading, colSpan = 6, gutter = 16 }: Props) {
  return (
    <Row gutter={[gutter, gutter]}>
      {items.map((item, idx) => (
        <Col span={colSpan} xs={12} sm={colSpan} key={idx}>
          <Card hoverable size="small">
            {loading ? (
              <Skeleton active paragraph={false} />
            ) : (
              <Statistic
                title={item.title}
                value={item.value}
                prefix={item.prefix}
                valueStyle={{ fontSize: 28, ...item.valueStyle }}
                suffix={item.suffix}
              />
            )}
          </Card>
        </Col>
      ))}
    </Row>
  )
}
