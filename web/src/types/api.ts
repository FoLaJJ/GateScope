import type {
  CheckType,
  FOFAImportResult,
  RiskLevel,
  Severity,
  TaskStatus,
} from './models'

export interface PaginatedResponse<T> {
  data: T[]
  total: number
  page?: number
  limit?: number
  pages?: number
}

export interface LoginResponse {
  token: string
}

export interface APIErrorResponse {
  code?: string
  error:
    | string
    | {
        code?: string | number
        message: string
        detail?: string
      }
  request_id?: string
}

export interface MessageResponse {
  message: string
}

export interface WSMessage<T = unknown> {
  type: string
  payload: T
  time: string
}

export interface TaskProgressPayload {
  task_id: string
  scanned: number
  progress: number
}

export interface PaginationParams {
  page?: number
  limit?: number
}

export interface TaskListParams extends PaginationParams {
  status?: TaskStatus
}

export interface AssetListParams extends PaginationParams {
  task_id?: string
  agent_type?: string
  ip?: string
  risk_level?: RiskLevel
}

export interface VulnListParams extends PaginationParams {
  task_id?: string
  asset_id?: string
  severity?: Severity
  cve_id?: string
  check_type?: CheckType
}

export interface FOFASearchRequest {
  query?: string
  limit: number
}

export interface FOFASearchResponse<T> {
  data: T[]
  total: number
}

export interface FOFAImportRequest extends FOFASearchRequest {
  task_name?: string
}

export type FOFAImportResponse = FOFAImportResult
