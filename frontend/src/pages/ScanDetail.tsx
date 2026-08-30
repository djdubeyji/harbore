import { useEffect, useState, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { ChevronLeft, Play, StopCircle, FileDown, RefreshCw, Terminal, Bug, FileText, RotateCw } from 'lucide-react'
import { getScan, startScan, cancelScan, getFindings, downloadReport, retestScan, reconcileRetest } from '../api/client'
import { useScanWS } from '../hooks/useScanWS'
import { GovReportModal } from '../components/GovReportModal'
import type { Scan, Finding, FailureLog, WSEvent } from '../types'
import { StatusBadge, SevBadge, ProgressBar, Spinner, StatCard } from '../components/ui'
import { formatDate, formatDuration, progressPct, MODULE_LABELS, cvssColor } from '../utils'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const
const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280'
}

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [showGov, setShowGov] = useState(false)
  const [retestId, setRetestId] = useState<string | null>(null)
  const [retestPhase, setRetestPhase] = useState<'running' | 'done' | null>(null)
  const [retestMsg, setRetestMsg] = useState('')

  const [scan, setScan]           = useState<Scan | null>(null)
  const [findings, setFindings]   = useState<Finding[]>([])
  const [failures, setFailures]   = useState<FailureLog[]>([])
  const [stats, setStats]         = useState<Record<string, number>>({})
  const [selected, setSelected]   = useState<Finding | null>(null)
  const [tab, setTab]             = useState<'findings' | 'failures' | 'events'>('findings')
  const [sevFilter, setSevFilter] = useState<string>('all')
  const [modFilter, setModFilter] = useState<string>('all')
  const [loading, setLoading]     = useState(true)
  const [actionLoading, setActionLoading] = useState(false)

  const loadFindings = useCallback(async () => {
    if (!id) return
    try {
      const r = await getFindings(id)
      setFindings(r.findings ?? [])
      setFailures(r.failures ?? [])
      setStats(r.stats ?? {})
    } catch { /* ignore */ }
  }, [id])

  const loadScan = useCallback(async () => {
    if (!id) return
    try { setScan(await getScan(id)) } catch { /* ignore */ }
  }, [id])

  useEffect(() => {
    Promise.all([loadScan(), loadFindings()]).finally(() => setLoading(false))
    const interval = setInterval(() => { loadScan(); loadFindings() }, 5000)
    return () => clearInterval(interval)
  }, [loadScan, loadFindings])

  const { events } = useScanWS(id, loadFindings)

  const onRetest = async () => {
    if (!id) return
    try {
      setRetestPhase('running'); setRetestMsg('Retest queued\u2026')
      const r = await retestScan(id)
      setRetestId(r.retest_scan_id)
    } catch { setRetestPhase(null); setRetestMsg('') }
  }

  useEffect(() => {
    if (!retestId || retestPhase !== 'running' || !id) return
    const iv = setInterval(async () => {
      try {
        const rs = await getScan(retestId)
        if (rs.status === 'completed') {
          clearInterval(iv)
          const res = await reconcileRetest(id, retestId)
          await loadFindings()
          setRetestPhase('done')
          setRetestMsg(`Retest complete \u2014 ${res.fixed} fixed \u00b7 ${res.still_open} still open`)
        } else if (rs.status === 'failed') {
          clearInterval(iv); setRetestPhase(null); setRetestMsg('Retest failed')
        } else {
          setRetestMsg(`Retesting\u2026 (${rs.status})`)
        }
      } catch { /* ignore */ }
    }, 4000)
    return () => clearInterval(iv)
  }, [retestId, retestPhase, id, loadFindings])

  // Update scan progress from WS
  useEffect(() => {
    const progressEvent = events.find(e => e.type === 'scan.progress')
    if (progressEvent && scan) {
      const p = progressEvent.payload as { completed_jobs: number; failed_jobs: number; total_jobs: number }
      setScan(s => s ? { ...s, completed_jobs: p.completed_jobs, failed_jobs: p.failed_jobs, total_jobs: p.total_jobs } : s)
    }
  }, [events])

  const handleStart = async () => {
    if (!id) return
    setActionLoading(true)
    try { await startScan(id); await loadScan() } finally { setActionLoading(false) }
  }
  const handleCancel = async () => {
    if (!id) return
    setActionLoading(true)
    try { await cancelScan(id); await loadScan() } finally { setActionLoading(false) }
  }

  const filteredFindings = findings.filter(f => {
    if (f.is_false_positive) return false
    if (sevFilter !== 'all' && f.severity !== sevFilter) return false
    if (modFilter !== 'all' && f.module !== modFilter) return false
    return true
  })

  const modules = [...new Set(findings.map(f => f.module))]
  const pct = scan ? progressPct(scan.completed_jobs, scan.failed_jobs, scan.total_jobs) : 0

  const chartData = SEV_ORDER
    .filter(s => (stats[s] ?? 0) > 0)
    .map(s => ({ name: s, count: stats[s] ?? 0, color: SEV_COLORS[s] }))

  if (loading) return (
    <div className="flex-1 flex items-center justify-center"><Spinner className="w-8 h-8" /></div>
  )
  if (!scan) return (
    <div className="flex-1 flex items-center justify-center text-gray-500">Scan not found</div>
  )

  return (
    <div className="flex-1 flex overflow-hidden">
      {showGov && <GovReportModal scanId={scan.id} scanName={scan.name} onClose={() => setShowGov(false)} />}
      {/* Main content */}
      <div className="flex-1 overflow-y-auto">
        <div className="px-6 py-4">
          {/* Back + title */}
          <button onClick={() => navigate('/')} className="flex items-center gap-1 text-gray-500 hover:text-gray-300 text-sm mb-4 transition-colors">
            <ChevronLeft className="w-4 h-4" /> Dashboard
          </button>
          <div className="flex items-start justify-between mb-4">
            <div>
              <h1 className="text-xl font-bold text-white">{scan.name}</h1>
              <div className="flex items-center gap-3 mt-1">
                <StatusBadge status={scan.status} />
                <span className="text-xs text-gray-500">{scan.config?.targets?.length ?? 0} targets · {scan.target_type}</span>
                <span className="text-xs text-gray-500">Duration: {formatDuration(scan.started_at, scan.finished_at)}</span>
              </div>
            </div>
            <div className="flex gap-2">
              {scan.status === 'pending' && (
                <button className="btn-primary" onClick={handleStart} disabled={actionLoading}>
                  <Play className="w-4 h-4" /> Start
                </button>
              )}
              {scan.status === 'running' && (
                <button className="btn-danger" onClick={handleCancel} disabled={actionLoading}>
                  <StopCircle className="w-4 h-4" /> Cancel
                </button>
              )}
              {scan.status === 'completed' && (
                <div className="flex gap-2">
                  <button className="btn-ghost" onClick={() => downloadReport(scan.id, 'docx')}>
                    <FileDown className="w-4 h-4" /> Word
                  </button>
                  <button className="btn-ghost" onClick={() => downloadReport(scan.id, 'pdf')}>
                    <FileDown className="w-4 h-4" /> PDF
                  </button>
                  <button className="btn-ghost" onClick={() => setShowGov(true)}>
                    <FileText className="w-4 h-4" /> ISMS DOCX
                  </button>
                  <button className="btn-ghost" onClick={onRetest} disabled={retestPhase === 'running'}>
                    <RotateCw className={`w-4 h-4 ${retestPhase === 'running' ? 'animate-spin' : ''}`} /> {retestPhase === 'running' ? 'Retesting\u2026' : 'Retest'}
                  </button>
                  {retestMsg && <span className="text-xs text-gray-400 self-center ml-1">{retestMsg}</span>}
                </div>
              )}
              <button className="btn-ghost" onClick={loadScan}><RefreshCw className="w-4 h-4" /></button>
            </div>
          </div>

          {/* Progress */}
          {(scan.status === 'running' || scan.status === 'completed') && (
            <div className="card px-4 py-3 mb-4">
              <div className="flex items-center justify-between text-xs text-gray-500 mb-2">
                <span>{scan.completed_jobs} / {scan.total_jobs} jobs complete · {scan.failed_jobs} failed</span>
                <span>{pct}%</span>
              </div>
              <ProgressBar pct={pct} />
            </div>
          )}

          {/* Stats */}
          <div className="grid grid-cols-5 gap-2 mb-4">
            {SEV_ORDER.map(s => (
              <button
                key={s}
                onClick={() => setSevFilter(sevFilter === s ? 'all' : s)}
                className={`card px-3 py-2 text-left transition-colors hover:bg-surface-3 ${sevFilter === s ? 'ring-1 ring-inset ring-accent-blue/40' : ''}`}
              >
                <div className="text-xs text-gray-500 capitalize mb-0.5">{s}</div>
                <div className="text-xl font-bold" style={{ color: SEV_COLORS[s] }}>{stats[s] ?? 0}</div>
              </button>
            ))}
          </div>

          {/* Chart (only if findings exist) */}
          {chartData.length > 0 && (
            <div className="card px-4 py-4 mb-4">
              <div className="text-xs text-gray-500 mb-3">Findings by severity</div>
              <ResponsiveContainer width="100%" height={80}>
                <BarChart data={chartData} barSize={32}>
                  <XAxis dataKey="name" tick={{ fontSize: 11, fill: '#6b7280' }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 11, fill: '#6b7280' }} axisLine={false} tickLine={false} width={24} />
                  <Tooltip
                    contentStyle={{ background: '#1a1a1e', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, fontSize: 12 }}
                    cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                  />
                  <Bar dataKey="count" radius={[3,3,0,0]}>
                    {chartData.map((d, i) => <Cell key={i} fill={d.color} fillOpacity={0.8} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Tabs */}
          <div className="flex items-center gap-1 mb-3 border-b border-border pb-3">
            {(['findings', 'failures', 'events'] as const).map(t => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`px-3 py-1.5 rounded text-sm transition-colors ${tab === t ? 'bg-accent-blue/15 text-accent-blue' : 'text-gray-500 hover:text-gray-300'}`}
              >
                {t === 'findings' ? `Findings (${filteredFindings.length})` :
                 t === 'failures' ? `Failures (${failures.length})` :
                 `Events (${events.length})`}
              </button>
            ))}
            {tab === 'findings' && (
              <div className="ml-auto flex gap-2">
                <select className="input w-32 py-1 text-xs" value={modFilter} onChange={e => setModFilter(e.target.value)}>
                  <option value="all">All modules</option>
                  {modules.map(m => <option key={m} value={m}>{MODULE_LABELS[m] ?? m}</option>)}
                </select>
              </div>
            )}
          </div>

          {/* Findings tab */}
          {tab === 'findings' && (
            <div className="space-y-1.5">
              {filteredFindings.length === 0 ? (
                <div className="text-center text-gray-600 py-12 text-sm">
                  {scan.status === 'running' ? 'Scanning in progress — findings will appear here' : 'No findings'}
                </div>
              ) : filteredFindings.map(f => (
                <button
                  key={f.id}
                  onClick={() => setSelected(selected?.id === f.id ? null : f)}
                  className={`w-full text-left card px-4 py-3 hover:bg-surface-3 transition-colors ${selected?.id === f.id ? 'ring-1 ring-inset ring-accent-blue/40' : ''}`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <SevBadge sev={f.severity} />
                        <span className="text-xs text-gray-500">{MODULE_LABELS[f.module] ?? f.module}</span>
                        {f.pci_requirement && <span className="text-[10px] text-pink-400/80 bg-pink-400/10 px-1.5 py-0.5 rounded border border-pink-400/20">{f.pci_requirement.split(' ').slice(0,2).join(' ')}</span>}
                        {f.owasp_ref && <span className="text-[10px] text-gray-600">{f.owasp_ref.split(' ')[0]}</span>}
                        {f.status === 'fixed' && <span className="text-[10px] text-emerald-400 bg-emerald-400/10 px-1.5 py-0.5 rounded border border-emerald-400/20">Fixed</span>}
                        {f.status !== 'fixed' && f.retested_at && <span className="text-[10px] text-amber-400 bg-amber-400/10 px-1.5 py-0.5 rounded border border-amber-400/20">Still open</span>}
                      </div>
                      <div className="font-medium text-gray-200 mt-1 text-sm">{f.title}</div>
                      <div className="text-xs text-gray-500 mt-0.5 truncate">{f.endpoint}</div>
                    </div>
                    <div className="flex-shrink-0 text-right">
                      {f.cvss_score != null && (
                        <div className={`text-sm font-bold font-mono ${cvssColor(f.cvss_score)}`}>{f.cvss_score.toFixed(1)}</div>
                      )}
                      {f.cwe_id && <div className="text-[10px] text-gray-600 mt-0.5">{f.cwe_id}</div>}
                    </div>
                  </div>

                  {/* Expanded finding */}
                  {selected?.id === f.id && (
                    <div className="mt-4 pt-4 border-t border-border space-y-4" onClick={e => e.stopPropagation()}>
                      <div>
                        <div className="label mb-1">Description</div>
                        <p className="text-sm text-gray-300 leading-relaxed">{f.description}</p>
                      </div>
                      {f.ai_remediation && (
                        <div>
                          <div className="label mb-1">AI Remediation</div>
                          <p className="text-sm text-gray-300 leading-relaxed">{f.ai_remediation}</p>
                        </div>
                      )}
                      {f.endpoint && (
                        <div>
                          <div className="label mb-1">Endpoint</div>
                          <div className="code-block text-gray-300">{f.method && <span className="text-blue-400 mr-2">{f.method}</span>}{f.endpoint}</div>
                        </div>
                      )}
                      {f.request && (
                        <div>
                          <div className="label mb-1">Request</div>
                          <pre className="code-block text-gray-400 max-h-48 overflow-y-auto whitespace-pre-wrap">{f.request}</pre>
                        </div>
                      )}
                      {f.response && (
                        <div>
                          <div className="label mb-1">Response</div>
                          <pre className="code-block text-gray-400 max-h-48 overflow-y-auto whitespace-pre-wrap">{f.response}</pre>
                        </div>
                      )}
                      <div className="flex flex-wrap gap-3 text-xs text-gray-600">
                        {f.owasp_ref && <span>{f.owasp_ref}</span>}
                        {f.pci_requirement && <span className="text-pink-400/70">{f.pci_requirement}</span>}
                        {f.cwe_id && <span>{f.cwe_id}</span>}
                        <span className="ml-auto">{formatDate(f.created_at)}</span>
                      </div>
                    </div>
                  )}
                </button>
              ))}
            </div>
          )}

          {/* Failures tab */}
          {tab === 'failures' && (
            <div className="space-y-2">
              {failures.length === 0 ? (
                <div className="text-center text-gray-600 py-12 text-sm">No failed jobs</div>
              ) : failures.map(f => (
                <div key={f.id} className="card px-4 py-3">
                  <div className="flex items-center gap-2 mb-1">
                    <Bug className="w-3.5 h-3.5 text-red-400" />
                    <span className="text-xs text-gray-500">{MODULE_LABELS[f.module] ?? f.module}</span>
                    <span className="text-xs text-gray-600">· {f.attempts} attempt{f.attempts !== 1 ? 's' : ''}</span>
                  </div>
                  <div className="text-sm text-gray-300 font-mono truncate">{f.target}</div>
                  <div className="text-xs text-red-400/70 mt-1">{f.final_error}</div>
                </div>
              ))}
            </div>
          )}

          {/* Events tab */}
          {tab === 'events' && (
            <div className="space-y-1">
              {events.length === 0 ? (
                <div className="text-center text-gray-600 py-12 text-sm flex flex-col items-center gap-2">
                  <Terminal className="w-6 h-6" />
                  Waiting for events…
                </div>
              ) : events.map((e, i) => (
                <div key={i} className="flex items-start gap-3 px-3 py-2 text-xs rounded hover:bg-surface-3">
                  <span className="text-gray-600 font-mono flex-shrink-0 w-28">
                    {new Date().toLocaleTimeString()}
                  </span>
                  <span className={`flex-shrink-0 font-mono ${
                    e.type.includes('finding') ? 'text-orange-400' :
                    e.type.includes('completed') ? 'text-green-400' :
                    e.type.includes('failed') ? 'text-red-400' : 'text-blue-400'
                  }`}>{e.type}</span>
                  <span className="text-gray-500 truncate">{JSON.stringify(e.payload)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
