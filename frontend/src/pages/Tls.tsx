import { useEffect, useState } from 'react'
import { Lock, Plus, RefreshCw, Trash2, ShieldAlert, ShieldCheck } from 'lucide-react'
import { listCertificates, checkCertificate, deleteCertificate } from '../api/client'
import type { Certificate } from '../types'

function daysUntil(iso?: string | null): number | null {
  if (!iso) return null
  return Math.floor((new Date(iso).getTime() - Date.now()) / 86400000)
}

// Alarm thresholds: 30 / 15 / 7 / 1 days
function expiryBadge(d: number | null) {
  if (d === null) return { cls: 'sev-info', text: 'unknown' }
  if (d < 0) return { cls: 'sev-critical', text: `expired ${-d}d ago` }
  if (d <= 1) return { cls: 'sev-critical', text: `${d}d left` }
  if (d <= 7) return { cls: 'sev-high', text: `${d}d left` }
  if (d <= 15) return { cls: 'sev-medium', text: `${d}d left` }
  if (d <= 30) return { cls: 'sev-medium', text: `${d}d left` }
  return { cls: 'sev-low', text: `${d}d left` }
}

export function TlsPage() {
  const [certs, setCerts] = useState<Certificate[]>([])
  const [host, setHost] = useState('')
  const [port, setPort] = useState('443')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const load = async () => { try { setCerts(await listCertificates()) } catch { /* ignore */ } }
  useEffect(() => { load() }, [])

  const add = async () => {
    if (!host) return
    setBusy(true); setErr(null)
    try {
      await checkCertificate(host.trim(), parseInt(port) || 443)
      setHost(''); setPort('443'); await load()
    } catch (e) { setErr(e instanceof Error ? e.message : 'Failed') }
    finally { setBusy(false) }
  }
  const refresh = async (c: Certificate) => { try { await checkCertificate(c.host, c.port); await load() } catch { /* ignore */ } }
  const remove = async (c: Certificate) => { try { await deleteCertificate(c.id); await load() } catch { /* ignore */ } }

  const soon = certs.filter(c => { const d = daysUntil(c.not_after); return d !== null && d <= 30 }).length

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="max-w-5xl mx-auto px-6 py-8">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-lg bg-accent-amber/15 border border-border flex items-center justify-center">
            <Lock className="w-5 h-5 text-accent-amber" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">TLS Certificate Management</h1>
            <p className="text-xs text-gray-500 mt-0.5">Monitor certificates and get alerted before they expire</p>
          </div>
          {soon > 0 && <span className="badge sev-high ml-auto"><ShieldAlert className="w-3 h-3 mr-1" />{soon} expiring ≤30d</span>}
        </div>

        <div className="card p-5 mb-5">
          <label className="label">Monitor a host</label>
          <div className="flex flex-wrap gap-2 mt-1">
            <input value={host} onChange={e => setHost(e.target.value)} onKeyDown={e => e.key === 'Enter' && add()}
              placeholder="example.com  or  10.0.0.5" className="input max-w-xs" />
            <input value={port} onChange={e => setPort(e.target.value)} className="input w-24" placeholder="443" />
            <button onClick={add} disabled={busy || !host} className="btn-primary text-sm disabled:opacity-50">
              <Plus className="w-3.5 h-3.5" /> {busy ? 'Checking…' : 'Add & check'}
            </button>
          </div>
          <p className="text-[11px] text-gray-600 mt-2">Alarm thresholds: <span className="text-accent-amber">30 · 15 · 7 · 1 days</span> before expiry. The orchestrator pulls the live cert chain directly.</p>
          {err && <p className="text-xs text-[#FF6B7D] mt-2">{err}</p>}
        </div>

        {certs.length === 0 ? (
          <div className="card p-10 text-center text-sm text-gray-500">No certificates monitored yet — add a host above.</div>
        ) : (
          <div className="space-y-2">
            {certs.map(c => {
              const d = daysUntil(c.not_after)
              const b = expiryBadge(d)
              const weak = c.tls_version === 'TLS 1.0' || c.tls_version === 'TLS 1.1'
              return (
                <div key={c.id} className="card p-4">
                  <div className="flex items-center gap-3">
                    {c.error
                      ? <ShieldAlert className="w-4 h-4 text-[#FF6B7D] flex-shrink-0" />
                      : <ShieldCheck className="w-4 h-4 text-accent-emerald flex-shrink-0" />}
                    <div className="min-w-0">
                      <div className="text-sm font-medium text-white truncate">{c.host}:{c.port}</div>
                      <div className="text-[11px] text-gray-500 truncate">
                        {c.error ? <span className="text-[#FF6B7D]">{c.error}</span> : <>{c.common_name || '—'} · issued by {c.issuer || '—'}</>}
                      </div>
                    </div>
                    <div className="ml-auto flex items-center gap-2 flex-shrink-0">
                      {!c.error && <span className={`badge ${b.cls}`}>{b.text}</span>}
                      {weak && <span className="badge sev-high">{c.tls_version}</span>}
                      <button onClick={() => refresh(c)} className="p-1.5 rounded hover:bg-white/5 text-gray-400" title="Re-check"><RefreshCw className="w-3.5 h-3.5" /></button>
                      <button onClick={() => remove(c)} className="p-1.5 rounded hover:bg-white/5 text-gray-400" title="Remove"><Trash2 className="w-3.5 h-3.5" /></button>
                    </div>
                  </div>
                  {!c.error && (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-1 mt-3 pl-7 text-[11px]">
                      <Meta k="Expires" v={c.not_after ? new Date(c.not_after).toLocaleDateString() : '—'} />
                      <Meta k="Key" v={c.key_type ? `${c.key_type} ${c.key_bits}` : '—'} />
                      <Meta k="Signature" v={c.sig_alg || '—'} />
                      <Meta k="Protocol" v={c.tls_version || '—'} />
                      {c.sans && c.sans.length > 0 && <div className="col-span-2 md:col-span-4"><Meta k="SANs" v={c.sans.slice(0, 6).join(', ') + (c.sans.length > 6 ? ` +${c.sans.length - 6}` : '')} /></div>}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

function Meta({ k, v }: { k: string; v: string }) {
  return <div className="flex gap-1.5"><span className="text-gray-600">{k}:</span><span className="text-gray-300 truncate">{v}</span></div>
}
