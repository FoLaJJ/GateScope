import type { AlertRecord, AlertRule, Asset, DashboardStats, IntelResult, Task, Vulnerability } from '@/types'

export function makeTask(overrides: Partial<Task> = {}): Task {
  return {
    id: 'task-1',
    name: '默认任务',
    status: 'completed',
    type: 'instant',
    scan_depth: 'l3',
    targets: '1.1.1.1',
    ports: '80,443',
    concurrency: 100,
    timeout: 3,
    enable_mdns: true,
    total_targets: 1,
    scanned_targets: 1,
    open_ports: 1,
    found_agents: 1,
    found_vulns: 1,
    progress_percent: 100,
    created_at: '2026-03-20T10:00:00Z',
    updated_at: '2026-03-20T10:05:00Z',
    started_at: '2026-03-20T10:00:10Z',
    finished_at: '2026-03-20T10:05:00Z',
    ...overrides,
  }
}

export function makeAsset(overrides: Partial<Asset> = {}): Asset {
  return {
    id: 'asset-1',
    task_id: 'task-1',
    ip: '1.1.1.1',
    port: 18789,
    agent_type: 'openclaw',
    agent_id: 'agent-1',
    version: '1.0.0',
    auth_mode: 'token',
    risk_level: 'high',
    confidence: 92,
    status: 'active',
    country: 'CN',
    province: 'Shanghai',
    city: 'Shanghai',
    isp: 'ISP',
    asn: 'AS1234',
    metadata: { raw: 'agent metadata' },
    first_seen_at: '2026-03-20T10:00:00Z',
    last_seen_at: '2026-03-20T10:05:00Z',
    ...overrides,
  }
}

export function makeVulnerability(overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id: 'vuln-1',
    asset_id: 'asset-1',
    task_id: 'task-1',
    cve_id: 'CVE-2026-0001',
    title: '默认漏洞',
    description: '默认漏洞描述',
    severity: 'critical',
    cvss: 9.8,
    check_type: 'cve_match',
    evidence: 'PoC evidence',
    remediation: '升级到最新版本',
    detected_at: '2026-03-20T10:05:00Z',
    ...overrides,
  }
}

export function makeAlertRule(overrides: Partial<AlertRule> = {}): AlertRule {
  return {
    name: '严重漏洞',
    event: 'vuln.detected',
    condition: 'severity_gte',
    threshold: 'high',
    enabled: true,
    ...overrides,
  }
}

export function makeAlertRecord(overrides: Partial<AlertRecord> = {}): AlertRecord {
  return {
    id: 'alert-1',
    event_type: 'vuln.detected',
    rule_name: '严重漏洞',
    data: { cve_id: 'CVE-2026-0001', severity: 'critical' },
    sent: true,
    created_at: '2026-03-20T10:06:00Z',
    ...overrides,
  }
}

export function makeDashboardStats(overrides: Partial<DashboardStats> = {}): DashboardStats {
  return {
    total_tasks: 12,
    total_assets: 20,
    total_vulns: 7,
    risk_distribution: { critical: 2, high: 3, medium: 1, low: 4, info: 10 },
    severity_distribution: { critical: 2, high: 2, medium: 1, low: 1, info: 1 },
    agent_type_distribution: { openclaw: 10, hermes: 5 },
    recent_tasks: [],
    recent_vulns: [],
    auth_distribution: {},
    ...overrides,
  }
}

export function makeIntelResult(overrides: Partial<IntelResult> = {}): IntelResult {
  return {
    ip: '8.8.8.8',
    port: 443,
    protocol: 'https',
    host: 'example.com',
    title: 'OpenClaw',
    banner: 'banner',
    country: 'US',
    city: 'Mountain View',
    source: 'fofa',
    ...overrides,
  }
}
