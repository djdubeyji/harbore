import type {
  Scan, Finding, FindingsResponse, ScanProgress, User, CreateScanRequest,
  DebugLogsResponse, DebugJobsResponse, Organization, Certificate, Asset,
} from '../types'

const BASE = '/api/v1'

function getToken(): string {
  return localStorage.getItem('harbore_token') ?? ''
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken()
  const res = await fetch(BASE + path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(localStorage.getItem('harbore_org') ? { 'X-Org-Id': localStorage.getItem('harbore_org')! } : {}),
      ...(options.headers ?? {}),
    },
  })

  if (res.status === 401) {
    localStorage.removeItem('harbore_token')
    window.location.href = '/login'
    throw new Error('Unauthorized')
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(err.error ?? 'Request failed')
  }

  return res.json()
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

export async function login(email: string, password: string): Promise<{ token: string; user: User }> {
  const data = await request<{ token: string; user: User }>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })
  localStorage.setItem('harbore_token', data.token)
  return data
}

export async function getMe(): Promise<User> {
  return request<User>('/auth/me')
}

export function logout() {
  localStorage.removeItem('harbore_token')
  window.location.href = '/login'
}

// ─── Scans ────────────────────────────────────────────────────────────────────

export async function createScan(req: CreateScanRequest): Promise<Scan> {
  return request<Scan>('/scans', { method: 'POST', body: JSON.stringify(req) })
}

export async function listScans(): Promise<Scan[]> {
  const data = await request<Scan[] | null>('/scans')
  return data ?? []
}

export async function getScan(id: string): Promise<Scan> {
  return request<Scan>(`/scans/${id}`)
}

export async function startScan(id: string): Promise<{ message: string; total_jobs: number; num_containers: number; estimated_mins: number }> {
  return request(`/scans/${id}/start`, { method: 'POST' })
}

export async function cancelScan(id: string): Promise<void> {
  await request(`/scans/${id}/cancel`, { method: 'POST' })
}

export async function getScanProgress(id: string): Promise<ScanProgress> {
  return request<ScanProgress>(`/scans/${id}/progress`)
}

// ─── Findings ─────────────────────────────────────────────────────────────────

export async function getFindings(scanId: string): Promise<FindingsResponse> {
  return request<FindingsResponse>(`/scans/${scanId}/findings`)
}

// ─── Reports ──────────────────────────────────────────────────────────────────

export async function downloadReport(scanId: string, format: 'docx' | 'pdf') {
  const token = getToken()
  const res = await fetch(`/api/v1/scans/${scanId}/report?format=${format}`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!res.ok) throw new Error('Report generation failed')
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `harbore-scan-${scanId.slice(0, 8)}.${format}`
  a.click()
  URL.revokeObjectURL(url)
}

// ─── Debug console (TEMPORARY) ────────────────────────────────────────────────

export async function getDebugLogs(params: {
  level?: string; source?: string; q?: string; since?: number; limit?: number
} = {}): Promise<DebugLogsResponse> {
  const qs = new URLSearchParams()
  if (params.level && params.level !== 'all') qs.set('level', params.level)
  if (params.source && params.source !== 'all') qs.set('source', params.source)
  if (params.q) qs.set('q', params.q)
  if (params.since) qs.set('since', String(params.since))
  if (params.limit) qs.set('limit', String(params.limit))
  const query = qs.toString()
  return request<DebugLogsResponse>(`/debug/logs${query ? `?${query}` : ''}`)
}

export async function getDebugJobs(params: {
  status?: string; scanId?: string; limit?: number
} = {}): Promise<DebugJobsResponse> {
  const qs = new URLSearchParams()
  if (params.status && params.status !== 'all') qs.set('status', params.status)
  if (params.scanId) qs.set('scan_id', params.scanId)
  if (params.limit) qs.set('limit', String(params.limit))
  const query = qs.toString()
  return request<DebugJobsResponse>(`/debug/jobs${query ? `?${query}` : ''}`)
}

// ─── WebSocket ────────────────────────────────────────────────────────────────

export function connectScanWS(scanId: string, onMessage: (event: MessageEvent) => void): WebSocket {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  const host = window.location.host
  const token = getToken()
  // WS handshakes can't send an Authorization header, so pass the JWT as a query param.
  const ws = new WebSocket(`${proto}://${host}/ws/scans/${scanId}?token=${encodeURIComponent(token)}`)
  ws.onmessage = onMessage
  ws.onerror = (e) => console.error('[ws] error', e)
  return ws
}

// ─── Organizations ────────────────────────────────────────────────────────────

export async function getOrgs(): Promise<Organization[]> {
  const data = await request<Organization[] | null>('/orgs')
  return data ?? []
}

export async function createOrg(name: string): Promise<Organization> {
  return request<Organization>('/orgs', { method: 'POST', body: JSON.stringify({ name }) })
}

export async function addOrgMember(orgId: string, email: string, role = 'member'): Promise<void> {
  await request(`/orgs/${orgId}/members`, { method: 'POST', body: JSON.stringify({ email, role }) })
}

// ─── Settings ─────────────────────────────────────────────────────────────────

export async function updateProfile(name: string, avatar: string): Promise<User> {
  return request<User>('/auth/profile', { method: 'PUT', body: JSON.stringify({ name, avatar }) })
}

export async function changePassword(current_password: string, new_password: string): Promise<void> {
  await request('/auth/password', { method: 'POST', body: JSON.stringify({ current_password, new_password }) })
}

// ─── TLS certificates ─────────────────────────────────────────────────────────

export async function listCertificates(): Promise<Certificate[]> {
  const data = await request<Certificate[] | null>('/tls/checks')
  return data ?? []
}

export async function checkCertificate(host: string, port = 443): Promise<Certificate> {
  return request<Certificate>('/tls/checks', { method: 'POST', body: JSON.stringify({ host, port }) })
}

export async function deleteCertificate(id: string): Promise<void> {
  await request(`/tls/checks/${id}`, { method: 'DELETE' })
}

// ─── Assets (CMDB) ────────────────────────────────────────────────────────────

export async function getAssets(): Promise<Asset[]> {
  const data = await request<Asset[] | null>('/assets')
  return data ?? []
}

export async function importAssets(payload: unknown): Promise<{ imported: number; assets: Asset[] }> {
  return request('/assets/import', { method: 'POST', body: JSON.stringify(payload) })
}

export async function updateAsset(id: string, patch: { label?: string; owner?: string; criticality?: string; classification?: string }): Promise<void> {
  await request(`/assets/${id}`, { method: 'PATCH', body: JSON.stringify(patch) })
}

export async function clearAssets(): Promise<void> {
  await request('/assets', { method: 'DELETE' })
}

// ─── ISMS governance report ───────────────────────────────────────────────────

export async function generateGovernanceReport(scanId: string, fields: Record<string, unknown>) {
  const token = getToken()
  const orgId = localStorage.getItem('harbore_org')
  const res = await fetch(`/api/v1/scans/${scanId}/report/governance`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...(orgId ? { 'X-Org-Id': orgId } : {}),
    },
    body: JSON.stringify(fields),
  })
  if (!res.ok) throw new Error('Report generation failed')
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `harbore-isms-${scanId.slice(0, 8)}.docx`
  a.click()
  URL.revokeObjectURL(url)
}

// ─── Retest ───────────────────────────────────────────────────────────────────

export async function retestScan(scanId: string): Promise<{ retest_scan_id: string; parent_scan_id: string; total_jobs: number }> {
  return request(`/scans/${scanId}/retest`, { method: 'POST' })
}

export async function reconcileRetest(parentId: string, retestScanId: string): Promise<{ fixed: number; still_open: number }> {
  return request(`/scans/${parentId}/reconcile`, { method: 'POST', body: JSON.stringify({ retest_scan_id: retestScanId }) })
}
