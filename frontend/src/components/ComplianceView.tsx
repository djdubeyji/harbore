import { useState } from 'react'
import { Download, ChevronRight, CheckCircle2, AlertTriangle, FileEdit, RefreshCw } from 'lucide-react'
import { downloadReport, type FrameworkResult, type ControlResult } from '../lib/compliance'

function statusBadge(c: ControlResult) {
  if (c.status === 'manual') return <span className="badge sev-medium"><FileEdit className="w-3 h-3 mr-1" />Manual</span>
  if (c.status === 'pass') return <span className="badge sev-low"><CheckCircle2 className="w-3 h-3 mr-1" />No findings</span>
  const cls = c.worst === 'critical' ? 'sev-critical' : c.worst === 'high' ? 'sev-high' : c.worst === 'medium' ? 'sev-medium' : 'sev-low'
  return <span className={`badge ${cls}`}><AlertTriangle className="w-3 h-3 mr-1" />{c.findings.length} · {c.worst}</span>
}

export function ComplianceView({ result, orgName, loading, onRecompute }: {
  result: FrameworkResult | null; orgName: string; loading: boolean; onRecompute: () => void
}) {
  const [open, setOpen] = useState<string | null>(null)
  if (loading || !result) {
    return <div className="card p-10 text-center text-sm text-gray-500">{loading ? 'Aggregating findings…' : 'No data'}</div>
  }
  const s = result.summary
  return (
    <>
      <div className="flex items-center gap-3 mb-4">
        <div className="flex-1 grid grid-cols-4 gap-3">
          <Stat k="Readiness" v={`${s.score}%`} accent />
          <Stat k="No findings" v={s.passed} color="#34D399" />
          <Stat k="Gaps" v={s.gaps} color="#FF6B7D" />
          <Stat k="Manual" v={s.manual} color="#FFC24D" />
        </div>
        <button onClick={onRecompute} className="btn-ghost text-sm" title="Recompute"><RefreshCw className="w-3.5 h-3.5" /></button>
        <button onClick={() => downloadReport(result, orgName)} className="btn-primary text-sm"><Download className="w-3.5 h-3.5" /> Report</button>
      </div>

      <div className="h-2 rounded-full bg-surface-3 overflow-hidden mb-5">
        <div className="h-full bg-gradient-to-r from-accent-gold to-accent-amber" style={{ width: `${s.score}%` }} />
      </div>

      <div className="space-y-1.5">
        {result.controls.map(c => (
          <div key={c.id} className="card overflow-hidden">
            <button
              onClick={() => setOpen(open === c.id ? null : c.id)}
              disabled={c.findings.length === 0}
              className="w-full flex items-center gap-3 px-4 py-3 text-left disabled:cursor-default"
            >
              <span className="text-xs font-bold text-accent-amber w-6 flex-shrink-0">{c.id}</span>
              <div className="min-w-0 flex-1">
                <div className="text-sm text-gray-200 truncate">{c.title}</div>
                <div className="text-[11px] text-gray-500">{c.category}</div>
              </div>
              {statusBadge(c)}
              {c.findings.length > 0 && <ChevronRight className={`w-4 h-4 text-gray-500 transition-transform ${open === c.id ? 'rotate-90' : ''}`} />}
            </button>
            {open === c.id && c.findings.length > 0 && (
              <div className="border-t border-border px-4 py-2 space-y-1.5 bg-surface-0/40">
                {c.findings.slice(0, 12).map(f => (
                  <div key={f.id} className="flex items-center gap-2 text-xs">
                    <span className={`sev-${f.severity} badge`}>{f.severity}</span>
                    <span className="text-gray-300 truncate">{f.title}</span>
                    {f.owasp_ref && <span className="text-gray-600 ml-auto flex-shrink-0">{f.owasp_ref}</span>}
                  </div>
                ))}
                {c.findings.length > 12 && <div className="text-[11px] text-gray-600">+{c.findings.length - 12} more</div>}
              </div>
            )}
          </div>
        ))}
      </div>

      <p className="text-[11px] text-gray-600 mt-4">
        Technical controls are mapped automatically from your scan findings. Manual-attestation controls
        (policies, physical, HR, incident processes) require organizational evidence. Not a formal certification.
      </p>
    </>
  )
}

function Stat({ k, v, color, accent }: { k: string; v: string | number; color?: string; accent?: boolean }) {
  return (
    <div className="card p-3">
      <div className="text-[11px] text-gray-500">{k}</div>
      <div className={`text-xl font-bold mt-0.5 ${accent ? 'text-accent-amber' : ''}`} style={color ? { color } : undefined}>{v}</div>
    </div>
  )
}
