import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Terminal, RefreshCw, Play, Pause, Search, Trash2, AlertTriangle,
  CheckCircle2, ListChecks, ScrollText,
} from 'lucide-react'
import { getDebugLogs, getDebugJobs } from '../api/client'
import type { LogEntry, DebugJob } from '../types'
import { Spinner, EmptyState } from '../components/ui'
import { MODULE_COLORS, MODULE_LABELS, formatDuration } from '../utils'

const LEVEL_COLOR: Record<string, string> = {
  error: 'text-red-400',
  warn:  'text-amber-400',
  info:  'text-gray-400',
}

const JOB_STATUS_STYLE: Record<string, string> = {
  queued:    'bg-gray-500/15 text-gray-400 border border-gray-500/25',
  running:   'bg-blue-500/15 text-blue-400 border border-blue-500/25 animate-pulse-slow',
  completed: 'bg-green-500/15 text-green-400 border border-green-500/25',
  failed:    'bg-red-500/15 text-red-400 border border-red-500/25',
  retrying:  'bg-amber-500/15 text-amber-400 border border-amber-500/25',
}

const LEVELS = ['all', 'info', 'warn', 'error'] as const
const JOB_STATUSES = ['all', 'completed', 'failed', 'running', 'queued', 'retrying'] as const
const UI_LOG_CAP = 2000

function logTime(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleTimeString('en-US', { hour12: false })
}

export function ConsolePage() {
  const [tab, setTab] = useState<'logs' | 'jobs'>('logs')

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-border flex-shrink-0">
        <div className="flex items-center gap-2.5">
          <Terminal className="w-5 h-5 text-accent-blue" />
          <h1 className="text-base font-semibold text-white">Debug Console</h1>
          <span className="badge bg-amber-500/15 text-amber-400 border border-amber-500/25 uppercase tracking-wide">
            Temporary
          </span>
        </div>
        <p className="text-xs text-gray-500 mt-1">
          Live orchestrator logs and job status across all scans — for diagnosing module execution.
          Disable with <span className="font-mono text-gray-400">DEBUG_CONSOLE=false</span>.
        </p>

        {/* Tabs */}
        <div className="flex gap-1 mt-4">
          <TabButton active={tab === 'logs'} onClick={() => setTab('logs')} icon={ScrollText} label="Logs" />
          <TabButton active={tab === 'jobs'} onClick={() => setTab('jobs')} icon={ListChecks} label="Jobs" />
        </div>
      </div>

      {tab === 'logs' ? <LogsTab /> : <JobsTab />}
    </div>
  )
}

function TabButton({ active, onClick, icon: Icon, label }: {
  active: boolean; onClick: () => void; icon: React.ComponentType<{ className?: string }>; label: string
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm transition-colors ${
        active ? 'bg-accent-blue/15 text-accent-blue' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
      }`}
    >
      <Icon className="w-3.5 h-3.5" />
      {label}
    </button>
  )
}

// ─── Logs tab ─────────────────────────────────────────────────────────────────

function LogsTab() {
  const [entries, setEntries] = useState<LogEntry[]>([])
  const [sources, setSources] = useState<string[]>([])
  const [counts, setCounts] = useState<Record<string, number>>({})
  const [enabled, setEnabled] = useState(true)
  const [level, setLevel] = useState<string>('all')
  const [source, setSource] = useState<string>('all')
  const [search, setSearch] = useState('')
  const [auto, setAuto] = useState(true)
  const [loading, setLoading] = useState(true)

  const lastIdRef = useRef(0)
  const scrollRef = useRef<HTMLDivElement>(null)
  const stickRef = useRef(true)

  // Reset the feed when server-side filters change.
  const filterKey = `${level}|${source}|${search}`
  useEffect(() => {
    lastIdRef.current = 0
    setEntries([])
    setLoading(true)
  }, [filterKey])

  const poll = useCallback(async () => {
    try {
      const r = await getDebugLogs({ level, source, q: search, since: lastIdRef.current, limit: 500 })
      setEnabled(r.enabled)
      setSources(r.sources ?? [])
      setCounts(r.counts ?? {})
      const incoming = r.entries ?? []
      if (incoming.length > 0) {
        lastIdRef.current = incoming[incoming.length - 1].id
        setEntries(prev => {
          const merged = [...prev, ...incoming]
          return merged.length > UI_LOG_CAP ? merged.slice(merged.length - UI_LOG_CAP) : merged
        })
      }
    } catch { /* transient — keep prior entries */ }
    finally { setLoading(false) }
  }, [level, source, search])

  useEffect(() => { poll() }, [poll])

  useEffect(() => {
    if (!auto) return
    const id = setInterval(poll, 2000)
    return () => clearInterval(id)
  }, [auto, poll])

  // Auto-scroll to the newest line unless the user has scrolled up.
  useEffect(() => {
    if (stickRef.current && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [entries])

  const onScroll = () => {
    const el = scrollRef.current
    if (!el) return
    stickRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40
  }

  return (
    <div className="flex-1 flex flex-col overflow-hidden px-6 py-4">
      {/* Controls */}
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <div className="flex gap-1">
          {LEVELS.map(l => (
            <button
              key={l}
              onClick={() => setLevel(l)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium capitalize transition-colors ${
                level === l ? 'bg-accent-blue/15 text-accent-blue' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
              }`}
            >
              {l}{l !== 'all' && counts[l] != null ? ` (${counts[l]})` : ''}
            </button>
          ))}
        </div>

        <select value={source} onChange={e => setSource(e.target.value)} className="input w-auto py-1 text-xs">
          <option value="all">All sources</option>
          {sources.map(s => <option key={s} value={s}>{s}</option>)}
        </select>

        <div className="relative flex-1 min-w-[180px] max-w-xs">
          <Search className="w-3.5 h-3.5 text-gray-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter text…"
            className="input pl-8 py-1 text-xs"
          />
        </div>

        <div className="flex gap-1 ml-auto">
          <button onClick={() => setAuto(a => !a)} className="btn-ghost text-xs py-1">
            {auto ? <><Pause className="w-3.5 h-3.5" /> Pause</> : <><Play className="w-3.5 h-3.5" /> Resume</>}
          </button>
          <button onClick={poll} className="btn-ghost text-xs py-1"><RefreshCw className="w-3.5 h-3.5" /> Refresh</button>
          <button onClick={() => { setEntries([]); lastIdRef.current = 0 }} className="btn-ghost text-xs py-1">
            <Trash2 className="w-3.5 h-3.5" /> Clear
          </button>
        </div>
      </div>

      {/* Log viewport */}
      {!enabled ? (
        <EmptyState icon={Terminal} title="Debug console is disabled"
          sub="The orchestrator was started with DEBUG_CONSOLE=false. Set it to true and restart to capture logs." />
      ) : loading && entries.length === 0 ? (
        <div className="flex-1 flex items-center justify-center"><Spinner className="w-6 h-6" /></div>
      ) : entries.length === 0 ? (
        <EmptyState icon={ScrollText} title="No log entries match" sub="Adjust the filters, or trigger a scan to generate activity." />
      ) : (
        <div
          ref={scrollRef}
          onScroll={onScroll}
          className="flex-1 overflow-y-auto code-block bg-surface-0 space-y-0.5 leading-relaxed"
        >
          {entries.map(e => (
            <div key={e.id} className="flex gap-2 hover:bg-white/[0.03] px-1 -mx-1 rounded">
              <span className="text-gray-600 flex-shrink-0 select-none">{logTime(e.time)}</span>
              <span className="text-gray-500 flex-shrink-0 select-none w-24 truncate" title={e.source}>[{e.source}]</span>
              <span className={`${LEVEL_COLOR[e.level] ?? 'text-gray-300'} whitespace-pre-wrap break-all`}>{e.message}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Jobs tab ─────────────────────────────────────────────────────────────────

function JobsTab() {
  const [jobs, setJobs] = useState<DebugJob[]>([])
  const [counts, setCounts] = useState<Record<string, number>>({})
  const [status, setStatus] = useState<string>('all')
  const [auto, setAuto] = useState(true)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const r = await getDebugJobs({ status, limit: 300 })
      setJobs(r.jobs ?? [])
      setCounts(r.counts ?? {})
    } catch { /* ignore transient */ }
    finally { setLoading(false) }
  }, [status])

  useEffect(() => { setLoading(true); load() }, [load])

  useEffect(() => {
    if (!auto) return
    const id = setInterval(load, 3000)
    return () => clearInterval(id)
  }, [auto, load])

  const total = Object.values(counts).reduce((a, b) => a + b, 0)

  return (
    <div className="flex-1 flex flex-col overflow-hidden px-6 py-4">
      {/* Summary strip */}
      <div className="flex flex-wrap gap-2 mb-3">
        <SummaryChip label="Total" value={total} />
        <SummaryChip label="Completed" value={counts.completed ?? 0} color="text-green-400" icon={CheckCircle2} />
        <SummaryChip label="Failed" value={counts.failed ?? 0} color="text-red-400" icon={AlertTriangle} />
        <SummaryChip label="Running" value={counts.running ?? 0} color="text-blue-400" />
        <SummaryChip label="Queued" value={counts.queued ?? 0} color="text-gray-400" />
        <SummaryChip label="Retrying" value={counts.retrying ?? 0} color="text-amber-400" />
      </div>

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <div className="flex gap-1">
          {JOB_STATUSES.map(s => (
            <button
              key={s}
              onClick={() => setStatus(s)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium capitalize transition-colors ${
                status === s ? 'bg-accent-blue/15 text-accent-blue' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
        <div className="flex gap-1 ml-auto">
          <button onClick={() => setAuto(a => !a)} className="btn-ghost text-xs py-1">
            {auto ? <><Pause className="w-3.5 h-3.5" /> Pause</> : <><Play className="w-3.5 h-3.5" /> Resume</>}
          </button>
          <button onClick={load} className="btn-ghost text-xs py-1"><RefreshCw className="w-3.5 h-3.5" /> Refresh</button>
        </div>
      </div>

      {/* Jobs table */}
      {loading && jobs.length === 0 ? (
        <div className="flex-1 flex items-center justify-center"><Spinner className="w-6 h-6" /></div>
      ) : jobs.length === 0 ? (
        <EmptyState icon={ListChecks} title="No jobs found"
          sub="Create and start a scan — each target × module pair becomes a job that shows up here." />
      ) : (
        <div className="flex-1 overflow-y-auto card">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-surface-2 border-b border-border">
              <tr className="text-left text-gray-500">
                <th className="px-3 py-2 font-medium">Module</th>
                <th className="px-3 py-2 font-medium">Target</th>
                <th className="px-3 py-2 font-medium">Status</th>
                <th className="px-3 py-2 font-medium">Try</th>
                <th className="px-3 py-2 font-medium">Duration</th>
                <th className="px-3 py-2 font-medium">Error</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map(j => (
                <tr key={j.id} className="border-b border-border/50 hover:bg-white/[0.02]">
                  <td className={`px-3 py-2 font-medium whitespace-nowrap ${MODULE_COLORS[j.module] ?? 'text-gray-300'}`}>
                    {MODULE_LABELS[j.module] ?? j.module}
                  </td>
                  <td className="px-3 py-2 font-mono text-gray-400 max-w-[240px] truncate" title={j.target}>{j.target}</td>
                  <td className="px-3 py-2">
                    <span className={`badge ${JOB_STATUS_STYLE[j.status] ?? 'bg-gray-500/15 text-gray-400'}`}>{j.status}</span>
                  </td>
                  <td className="px-3 py-2 text-gray-500 whitespace-nowrap">{j.attempt}/{j.max_attempts}</td>
                  <td className="px-3 py-2 text-gray-500 whitespace-nowrap">{formatDuration(j.started_at, j.finished_at)}</td>
                  <td className="px-3 py-2 text-red-400/90 max-w-[320px] truncate" title={j.error_message}>
                    {j.error_message || <span className="text-gray-600">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function SummaryChip({ label, value, color = 'text-white', icon: Icon }: {
  label: string; value: number; color?: string; icon?: React.ComponentType<{ className?: string }>
}) {
  return (
    <div className="card px-3 py-2 flex items-center gap-2 min-w-[92px]">
      {Icon && <Icon className={`w-3.5 h-3.5 ${color}`} />}
      <div>
        <div className={`text-lg font-bold leading-none ${color}`}>{value}</div>
        <div className="text-[10px] text-gray-500 mt-0.5">{label}</div>
      </div>
    </div>
  )
}
