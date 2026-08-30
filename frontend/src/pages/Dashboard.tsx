import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, Shield, SlidersHorizontal, RefreshCw } from 'lucide-react'
import { listScans } from '../api/client'
import type { Scan, Finding } from '../types'
import { StatusBadge, ProgressBar, EmptyState, Spinner } from '../components/ui'
import { formatDate, progressPct } from '../utils'
import { aggregateFindings, computeFramework } from '../lib/compliance'

type Basis = 'open' | 'found' | 'remediated'

const ALL_CARDS: { id: string; label: string; color?: string }[] = [
  { id: 'open_total',  label: 'Open vulnerabilities', color: '#FFAA00' },
  { id: 'critical',    label: 'Critical', color: '#FF6B7D' },
  { id: 'high',        label: 'High', color: '#FF9F45' },
  { id: 'medium',      label: 'Medium', color: '#FFD24D' },
  { id: 'low',         label: 'Low', color: '#5EC8FF' },
  { id: 'found',       label: 'Found (total)' },
  { id: 'remediated',  label: 'Remediated', color: '#34D399' },
  { id: 'pci',         label: 'PCI DSS gaps', color: '#FFAA00' },
  { id: 'nis2',        label: 'NIS2 gaps', color: '#FFAA00' },
  { id: 'dora',        label: 'DORA gaps', color: '#FFAA00' },
  { id: 'cra',         label: 'CRA gaps', color: '#FFAA00' },
  { id: 'scans_total', label: 'Total scans' },
  { id: 'running',     label: 'Running', color: '#5EC8FF' },
  { id: 'completed',   label: 'Completed', color: '#34D399' },
  { id: 'failed',      label: 'Failed', color: '#FF6B7D' },
]
const DEFAULT_CARDS = ['open_total', 'critical', 'high', 'medium', 'pci', 'nis2', 'dora', 'cra']
const CARDS_KEY = 'harbore_dash_cards'

function loadVisible(): string[] {
  try { const s = localStorage.getItem(CARDS_KEY); return s ? JSON.parse(s) : DEFAULT_CARDS } catch { return DEFAULT_CARDS }
}

export function DashboardPage() {
  const [scans, setScans] = useState<Scan[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [basis, setBasis] = useState<Basis>('open')
  const [visible, setVisible] = useState<string[]>(loadVisible)
  const [customizing, setCustomizing] = useState(false)
  const navigate = useNavigate()

  const load = () => {
    setLoading(true)
    Promise.all([listScans(), aggregateFindings()])
      .then(([s, f]) => { setScans(s); setFindings(f) })
      .catch(() => { setScans([]); setFindings([]) })
      .finally(() => setLoading(false))
  }
  useEffect(() => { load() }, [])

  const toggleCard = (id: string) => {
    setVisible(prev => {
      const next = prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
      localStorage.setItem(CARDS_KEY, JSON.stringify(next))
      return next
    })
  }

  const values = useMemo(() => {
    const found = findings
    const open = findings.filter(f => f.status !== 'fixed')
    const remediated = findings.filter(f => f.status === 'fixed')
    const set = basis === 'open' ? open : basis === 'remediated' ? remediated : found
    const sev = (s: string) => set.filter(f => f.severity === s).length
    const gaps = (k: string) => computeFramework(k, open).summary.gaps
    return {
      open_total: open.length,
      found: found.length,
      remediated: remediated.length,
      critical: sev('critical'), high: sev('high'), medium: sev('medium'), low: sev('low'),
      pci: gaps('pci'), nis2: gaps('nis2'), dora: gaps('dora'), cra: gaps('cra'),
      scans_total: scans.length,
      running: scans.filter(s => s.status === 'running').length,
      completed: scans.filter(s => s.status === 'completed').length,
      failed: scans.filter(s => s.status === 'failed').length,
    } as Record<string, number>
  }, [findings, scans, basis])

  const shown = ALL_CARDS.filter(c => visible.includes(c.id))

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="max-w-6xl mx-auto px-6 py-6">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h1 className="text-xl font-bold text-white">Dashboard</h1>
            <p className="text-sm text-gray-500 mt-0.5">Vulnerability & compliance posture across your organization</p>
          </div>
          <div className="flex items-center gap-2">
            <button className="btn-ghost text-sm" onClick={load} title="Refresh"><RefreshCw className="w-4 h-4" /></button>
            <button className="btn-ghost text-sm" onClick={() => setCustomizing(c => !c)}><SlidersHorizontal className="w-4 h-4" /> Customize</button>
            <button className="btn-primary" onClick={() => navigate('/scans/new')}><Plus className="w-4 h-4" /> New Scan</button>
          </div>
        </div>

        {/* severity basis filter */}
        <div className="flex items-center gap-2 mb-4">
          <span className="text-xs text-gray-500">Severity counts show:</span>
          {(['open', 'found', 'remediated'] as Basis[]).map(b => (
            <button key={b} onClick={() => setBasis(b)}
              className={`px-3 py-1 rounded-md text-xs border capitalize transition-colors ${basis === b ? 'border-accent-amber text-accent-amber bg-accent-amber/10' : 'border-border text-gray-400 hover:border-border-bright'}`}>
              {b}
            </button>
          ))}
        </div>

        {customizing && (
          <div className="card p-4 mb-4">
            <div className="text-xs text-gray-500 mb-2">Choose which cards to display</div>
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
              {ALL_CARDS.map(c => (
                <label key={c.id} className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer">
                  <input type="checkbox" checked={visible.includes(c.id)} onChange={() => toggleCard(c.id)} className="rounded border-border" />
                  {c.label}
                </label>
              ))}
            </div>
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center py-12"><Spinner /></div>
        ) : (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3 mb-6">
            {shown.map(c => (
              <div key={c.id} className="card p-4">
                <div className="text-[11px] text-gray-500">{c.label}</div>
                <div className="text-2xl font-bold mt-0.5" style={c.color ? { color: c.color } : undefined}>{values[c.id] ?? 0}</div>
              </div>
            ))}
            {shown.length === 0 && <div className="col-span-full text-center text-sm text-gray-600 py-6">No cards selected — click Customize to add some.</div>}
          </div>
        )}

        {/* Recent scans */}
        <div className="card overflow-hidden">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between">
            <span className="text-sm font-medium text-gray-300">Recent Scans</span>
          </div>
          {loading ? (
            <div className="flex items-center justify-center py-16"><Spinner /></div>
          ) : scans.length === 0 ? (
            <EmptyState icon={Shield} title="No scans yet" sub="Create your first scan to start discovering vulnerabilities" />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left">
                  <th className="px-4 py-2.5 text-xs text-gray-500 font-medium">Name</th>
                  <th className="px-4 py-2.5 text-xs text-gray-500 font-medium">Status</th>
                  <th className="px-4 py-2.5 text-xs text-gray-500 font-medium">Progress</th>
                  <th className="px-4 py-2.5 text-xs text-gray-500 font-medium">Modules</th>
                  <th className="px-4 py-2.5 text-xs text-gray-500 font-medium">Started</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {scans.map(scan => (
                  <tr key={scan.id} className="hover:bg-white/[0.02] cursor-pointer transition-colors" onClick={() => navigate(`/scans/${scan.id}`)}>
                    <td className="px-4 py-3">
                      <div className="font-medium text-gray-200">{scan.name}</div>
                      <div className="text-xs text-gray-500 mt-0.5">{scan.config?.targets?.length ?? 0} targets · {scan.target_type}</div>
                    </td>
                    <td className="px-4 py-3"><StatusBadge status={scan.status} /></td>
                    <td className="px-4 py-3 w-36">
                      <div className="text-xs text-gray-500 mb-1">{scan.completed_jobs}/{scan.total_jobs} jobs</div>
                      <ProgressBar pct={progressPct(scan.completed_jobs, scan.failed_jobs, scan.total_jobs)} />
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {(scan.modules ?? []).slice(0, 4).map(m => (
                          <span key={m} className="text-[10px] bg-surface-4 text-gray-400 px-1.5 py-0.5 rounded">{m}</span>
                        ))}
                        {(scan.modules?.length ?? 0) > 4 && <span className="text-[10px] text-gray-500">+{scan.modules.length - 4}</span>}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">{scan.started_at ? formatDate(scan.started_at) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}
