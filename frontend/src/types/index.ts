export type UserRole = 'admin' | 'analyst' | 'viewer'
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type TargetType = 'openapi' | 'postman' | 'graphql' | 'soap' | 'url_list' | 'har' | 'mcp' | 'single_url'

export interface User {
  id: string
  email: string
  name: string
  role: UserRole
  is_active: boolean
  avatar?: string
  created_at: string
}

export interface AssetPort { port: number; protocol?: string; service?: string; product?: string; version?: string }

export interface Asset {
  id: string
  ip_address: string
  hostname?: string
  mac_address?: string
  vendor?: string
  subnet?: string
  ports?: AssetPort[]
  is_scanner?: boolean
  label?: string
  owner?: string
  criticality?: string
  classification?: string
}

export interface Certificate {
  id: string
  org_id: string
  host: string
  port: number
  common_name: string
  issuer: string
  sans: string[]
  not_before?: string | null
  not_after?: string | null
  key_type: string
  key_bits: number
  sig_alg: string
  tls_version: string
  error: string
  last_checked_at: string
  created_at: string
}

export interface Organization {
  id: string
  name: string
  role?: string
  created_at: string
}

export interface Project {
  id: string
  owner_id: string
  name: string
  description: string
  created_at: string
}

export interface AuthConfig {
  headers: Record<string, string>
  cookies: Record<string, string>
  bearer: string
  user_a?: { username: string; password: string; headers: Record<string, string> }
  user_b?: { username: string; password: string; headers: Record<string, string> }
}

export interface ScanConfig {
  targets: string[]
  auth: AuthConfig
  nuclei_enabled: boolean
  module_config: Record<string, unknown>
}

export interface Scan {
  id: string
  project_id: string
  org_id?: string
  created_by: string
  name: string
  status: ScanStatus
  target_type: TargetType
  config: ScanConfig
  modules: string[]
  container_limit: number
  max_retries: number
  total_jobs: number
  completed_jobs: number
  failed_jobs: number
  created_at: string
  started_at?: string
  finished_at?: string
}

export interface Finding {
  id: string
  scan_id: string
  job_id?: string
  module: string
  title: string
  description: string
  severity: Severity
  cvss_score?: number
  cvss_vector?: string
  endpoint: string
  method: string
  request?: string
  response?: string
  owasp_ref?: string
  pci_requirement?: string
  cwe_id?: string
  ai_summary?: string
  ai_remediation?: string
  ai_priority?: number
  is_false_positive: boolean
  status?: string
  retested_at?: string | null
  created_at: string
}

export interface FailureLog {
  id: string
  scan_id: string
  target: string
  module: string
  attempts: number
  final_error: string
  created_at: string
}

export interface FindingsResponse {
  findings: Finding[]
  failures: FailureLog[]
  stats: Record<Severity, number>
  total: number
}

export interface ScanProgress {
  scan_id: string
  status: ScanStatus
  total_jobs: number
  completed_jobs: number
  failed_jobs: number
  progress_pct: number
}

export interface WSEvent {
  type: string
  scan_id: string
  payload: unknown
}

export interface CreateScanRequest {
  project_id: string
  name: string
  target_type: TargetType
  config: ScanConfig
  modules: string[]
  container_limit: number
  max_retries: number
}

// ─── Debug console (TEMPORARY) ────────────────────────────────────────────────

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'retrying'
export type LogLevel = 'info' | 'warn' | 'error'

export interface LogEntry {
  id: number
  time: string
  level: LogLevel
  source: string
  message: string
  raw: string
}

export interface DebugLogsResponse {
  entries: LogEntry[]
  sources: string[]
  counts: Record<string, number>
  enabled: boolean
}

export interface DebugJob {
  id: string
  scan_id: string
  target: string
  module: string
  status: JobStatus
  attempt: number
  max_attempts: number
  error_message: string
  container_id: string
  created_at: string
  started_at?: string
  finished_at?: string
}

export interface DebugJobsResponse {
  jobs: DebugJob[]
  counts: Record<string, number>
}
