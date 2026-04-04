export type TaskStatus = 'pending' | 'running' | 'completed' | 'failed' | 'paused' | 'cancelled'
export type ScanDepth = 'l1' | 'l2' | 'l3'
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type CheckType =
  | 'cve_match'
  | 'auth_check'
  | 'skills_check'
  | 'poc_verify'
  | 'ws_hijack'
  | 'path_traversal'
  | 'ssrf'

export type TaskType = 'instant' | 'scheduled'

export interface Task {
  id: string
  name: string
  description?: string
  status: TaskStatus
  type: TaskType
  cron_expr?: string
  scan_depth: ScanDepth
  targets: string
  ports?: string
  concurrency: number
  timeout: number
  enable_mdns: boolean
  total_targets: number
  scanned_targets: number
  open_ports: number
  found_agents: number
  found_vulns: number
  progress_percent: number
  error_message?: string
  created_at: string
  updated_at?: string
  started_at?: string
  finished_at?: string
}

export interface TaskEvent {
  id: string
  task_id: string
  event_type: string
  summary: string
  payload?: Record<string, unknown>
  event_time: string
  created_at?: string
}

export interface TaskTargetStatus {
  target: string
  status: 'identified' | 'scanned_no_agent' | 'pending' | 'scanning' | 'out_of_scope'
  status_text: string
  summary: string
  asset_id?: string
  ip?: string
  port?: number
  agent_type?: string
  version?: string
  auth_mode?: string
  risk_level?: RiskLevel
  confidence?: number
  vuln_count?: number
}

export interface CreateTaskRequest {
  name: string
  description?: string
  targets: string
  ports?: string
  scan_depth: ScanDepth
  type?: TaskType
  cron_expr?: string
  concurrency: number
  timeout: number
  enable_mdns: boolean
}

export interface Asset {
  id: string
  task_id: string
  ip: string
  port: number
  agent_type: string
  agent_id?: string
  version?: string
  auth_mode?: string
  risk_level: RiskLevel
  confidence: number
  status: string
  country?: string
  province?: string
  city?: string
  isp?: string
  asn?: string
  probe_details?: Record<string, unknown>
  metadata?: Record<string, unknown>
  first_seen_at?: string
  last_seen_at?: string
}

export interface Vulnerability {
  id: string
  asset_id: string
  task_id: string
  asset_ip?: string
  asset_port?: number
  agent_type?: string
  asset_version?: string
  auth_mode?: string
  risk_level?: RiskLevel
  asset_label?: string
  cve_id?: string
  cnnvd_id?: string
  ghsa_id?: string
  title: string
  description?: string
  description_zh?: string
  severity: Severity
  cvss: number
  check_type: CheckType
  evidence?: string
  remediation?: string
  detected_at?: string
}

export interface RuleCatalogMetadata {
  updated_at?: string
  verified_at?: string
  source_cutoff?: string
  source?: string
  notes?: string
  rule_count: number
  cve_count: number
  cnnvd_count: number
  ghsa_count: number
  poc_count: number
  consistent: boolean
  issues: string[]
}

export interface User {
  user_id: string
  username: string
  role: string
}

export interface DashboardStats {
  total_tasks: number
  total_assets: number
  total_vulns: number
  risk_distribution: Partial<Record<RiskLevel, number>>
  severity_distribution: Partial<Record<Severity, number>>
  agent_type_distribution: Record<string, number>
  recent_tasks?: Task[]
  recent_vulns?: Vulnerability[]
  auth_distribution?: Record<string, number>
}

export interface TargetImportResult {
  targets: string
  count: number
  message: string
}
