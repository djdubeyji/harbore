import { useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react'
import { Network, Download, Upload, Server, Cpu, X, Info } from 'lucide-react'
import { getAssets, importAssets, updateAsset, clearAssets } from '../api/client'
import type { Asset } from '../types'

const subnetOf = (a: Asset) => a.subnet || (a.ip_address.split('.').slice(0, 3).join('.') + '.0/24')

export function AssetDiscoveryPage() {
  const [method, setMethod] = useState<'agent' | 'container'>('agent')
  const [assets, setAssets] = useState<Asset[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = async () => { try { setAssets(await getAssets()) } catch { /* ignore */ } finally { setLoading(false) } }
  useEffect(() => { load() }, [])

  const ingest = async (text: string) => {
    try {
      const parsed = JSON.parse(text)
      if (!parsed || !Array.isArray(parsed.hosts)) throw new Error('missing "hosts" array')
      const res = await importAssets(parsed)
      setAssets(res.assets); setError(null)
    } catch (e) {
      setError('Could not import: ' + (e instanceof Error ? e.message : 'invalid JSON'))
    }
  }

  const patch = (id: string, p: Partial<Asset>) => {
    setAssets(prev => prev.map(a => (a.id === id ? { ...a, ...p } : a)))
    updateAsset(id, { label: p.label, owner: p.owner, criticality: p.criticality, classification: p.classification }).catch(() => {})
  }

  const clear = async () => { try { await clearAssets(); setAssets([]) } catch { /* ignore */ } }

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="max-w-5xl mx-auto px-6 py-8">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-lg bg-accent-amber/15 border border-border flex items-center justify-center">
            <Network className="w-5 h-5 text-accent-amber" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Asset Discovery</h1>
            <p className="text-xs text-gray-500 mt-0.5">Discover and inventory assets on your networks</p>
          </div>
          {assets.length > 0 && <button onClick={clear} className="btn-ghost text-xs ml-auto"><X className="w-3.5 h-3.5" /> Clear</button>}
        </div>

        {loading ? (
          <div className="card p-10 text-center text-sm text-gray-500">Loading assets…</div>
        ) : assets.length === 0 ? (
          <ImportPanel method={method} setMethod={setMethod} onIngest={ingest} error={error} />
        ) : (
          <AssetViews assets={assets} onPatch={patch} />
        )}
      </div>
    </div>
  )
}

function ImportPanel({ method, setMethod, onIngest, error }: {
  method: 'agent' | 'container'; setMethod: (m: 'agent' | 'container') => void; onIngest: (t: string) => void; error: string | null
}) {
  const [paste, setPaste] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)
  const onFile = (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]; if (!f) return
    const reader = new FileReader(); reader.onload = () => onIngest(reader.result as string); reader.readAsText(f)
  }
  return (
    <>
      <div className="grid md:grid-cols-2 gap-3 mb-5">
        <button onClick={() => setMethod('agent')} className={`card p-4 text-left transition-colors ${method === 'agent' ? 'border-accent-amber' : 'hover:border-border-bright'}`}>
          <div className="flex items-center gap-2 mb-1"><Server className="w-4 h-4 text-accent-amber" /><span className="font-semibold text-white text-sm">Agent import</span><span className="badge bg-accent-emerald/15 text-accent-emerald border border-accent-emerald/30 ml-auto">Recommended</span></div>
          <p className="text-xs text-gray-400">Run a small scanner on the network you want to inventory (your Mac, a laptop on the LAN, a VPC host). It sees the real network and produces a JSON file you import here.</p>
        </button>
        <button onClick={() => setMethod('container')} className={`card p-4 text-left transition-colors ${method === 'container' ? 'border-accent-amber' : 'hover:border-border-bright'}`}>
          <div className="flex items-center gap-2 mb-1"><Cpu className="w-4 h-4 text-accent-amber" /><span className="font-semibold text-white text-sm">In-container scan</span><span className="badge bg-surface-4 text-gray-400 border border-border ml-auto">Limited</span></div>
          <p className="text-xs text-gray-400">harbore's worker scans a subnet it can route to. On Docker Desktop / a Mac this <span className="text-accent-amber">cannot see your local Wi-Fi/LAN</span> — only reachable server subnets/VPCs.</p>
        </button>
      </div>

      {method === 'agent' ? (
        <div className="card p-6 space-y-4">
          <div className="flex items-center gap-3">
            <a href="/harbore-agent.py" download className="btn-primary text-sm"><Download className="w-3.5 h-3.5" /> Download agent</a>
            <span className="text-xs text-gray-500">requires <code className="text-accent-amber">nmap</code> + <code className="text-accent-amber">pip install python-nmap</code></span>
          </div>
          <ol className="text-sm text-gray-400 space-y-1.5 list-decimal list-inside marker:text-accent-amber/60">
            <li>On the machine/network to inventory, install nmap (macOS: <code className="text-gray-300">brew install nmap</code>).</li>
            <li>Run it: <code className="text-gray-300">sudo python3 harbore-agent.py --output scan_results.json</code></li>
            <li>Upload or paste the resulting <code className="text-gray-300">scan_results.json</code> below.</li>
          </ol>
          <div className="flex flex-wrap gap-3 items-start pt-2">
            <button onClick={() => fileRef.current?.click()} className="btn-ghost text-sm"><Upload className="w-3.5 h-3.5" /> Upload JSON</button>
            <input ref={fileRef} type="file" accept=".json,application/json" className="hidden" onChange={onFile} />
            <span className="text-xs text-gray-600 self-center">or paste:</span>
          </div>
          <textarea value={paste} onChange={e => setPaste(e.target.value)} placeholder='{ "scan_info": {...}, "hosts": [...] }' className="input font-mono text-xs h-28 resize-y" />
          <div className="flex items-center gap-3">
            <button onClick={() => onIngest(paste)} disabled={!paste.trim()} className="btn-primary text-sm disabled:opacity-50">Import</button>
            {error && <span className="text-xs text-[#FF6B7D]">{error}</span>}
          </div>
        </div>
      ) : (
        <div className="card p-6">
          <div className="flex items-start gap-2 text-sm text-gray-400">
            <Info className="w-4 h-4 text-accent-amber flex-shrink-0 mt-0.5" />
            <p>The in-container scanner reaches subnets the Docker network can route to (cloud VPCs, server segments) — useful for datacenter inventory, but on a Mac it can't discover your Wi-Fi/LAN devices because the container isn't on that network. For local discovery use the agent. Wiring the container scan into the worker is a follow-up.</p>
          </div>
        </div>
      )}
    </>
  )
}

function AssetViews({ assets, onPatch }: { assets: Asset[]; onPatch: (id: string, p: Partial<Asset>) => void }) {
  const [tab, setTab] = useState<'diagram' | 'cmdb'>('diagram')
  const subnets = useMemo(() => {
    const map: Record<string, Asset[]> = {}
    for (const a of assets) { (map[subnetOf(a)] ??= []).push(a) }
    return map
  }, [assets])
  const names = Object.keys(subnets)
  const [active, setActive] = useState(names[0] ?? '')
  const activeSubnet = names.includes(active) ? active : names[0] ?? ''

  return (
    <>
      <div className="flex items-center gap-2 mb-4 text-xs text-gray-500">
        <span className="badge bg-surface-3 border border-border text-gray-300">{assets.length} assets</span>
        <span className="badge bg-surface-3 border border-border text-gray-300">{names.length} network{names.length !== 1 ? 's' : ''}</span>
      </div>
      <div className="flex gap-1 mb-4 border-b border-border">
        {(['diagram', 'cmdb'] as const).map(t => (
          <button key={t} onClick={() => setTab(t)} className={`px-4 py-2 text-sm -mb-px border-b-2 transition-colors ${tab === t ? 'border-accent-amber text-accent-amber' : 'border-transparent text-gray-400 hover:text-gray-200'}`}>
            {t === 'diagram' ? 'Network Diagram' : 'CMDB'}
          </button>
        ))}
      </div>
      {names.length > 1 && (
        <div className="flex flex-wrap gap-1.5 mb-4">
          {names.map(s => (
            <button key={s} onClick={() => setActive(s)} className={`px-2.5 py-1 rounded-md text-xs border transition-colors ${activeSubnet === s ? 'border-accent-amber text-accent-amber bg-accent-amber/10' : 'border-border text-gray-400 hover:border-border-bright'}`}>{s}</button>
          ))}
        </div>
      )}
      {tab === 'diagram'
        ? <NetworkDiagram subnet={activeSubnet} assets={subnets[activeSubnet] ?? []} onPatch={onPatch} multi={names.length > 1} />
        : <CmdbTable assets={assets} onPatch={onPatch} />}
    </>
  )
}

function NetworkDiagram({ subnet, assets, onPatch, multi }: { subnet: string; assets: Asset[]; onPatch: (id: string, p: Partial<Asset>) => void; multi: boolean }) {
  const [sel, setSel] = useState<string | null>(null)
  const W = 720, H = 460, cx = W / 2, cy = H / 2, R = Math.min(W, H) / 2 - 90
  const label = (a: Asset) => a.label || a.hostname || a.ip_address
  return (
    <div className="grid md:grid-cols-[1fr_260px] gap-4">
      <div className="card p-2 overflow-hidden">
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto">
          {assets.map((a, i) => {
            const ang = (i / Math.max(assets.length, 1)) * Math.PI * 2 - Math.PI / 2
            const x = cx + R * Math.cos(ang), y = cy + R * Math.sin(ang)
            return <line key={'l' + i} x1={cx} y1={cy} x2={x} y2={y} stroke="rgba(255,122,0,0.25)" strokeWidth={1} />
          })}
          <g>
            <circle cx={cx} cy={cy} r={30} fill="rgba(255,122,0,0.15)" stroke="#FF7A00" strokeWidth={1.5} />
            <text x={cx} y={cy - 2} textAnchor="middle" fontSize={10} fill="#FFAA00" fontWeight="700">NETWORK</text>
            <text x={cx} y={cy + 11} textAnchor="middle" fontSize={8} fill="#94A3B8">{subnet}</text>
          </g>
          {assets.map((a, i) => {
            const ang = (i / Math.max(assets.length, 1)) * Math.PI * 2 - Math.PI / 2
            const x = cx + R * Math.cos(ang), y = cy + R * Math.sin(ang)
            const on = sel === a.id
            return (
              <g key={a.id} onClick={() => setSel(a.id)} className="cursor-pointer">
                <circle cx={x} cy={y} r={on ? 15 : 12} fill={a.is_scanner ? 'rgba(16,185,129,0.2)' : on ? 'rgba(255,170,0,0.3)' : 'rgba(255,122,0,0.12)'} stroke={a.is_scanner ? '#10B981' : '#FF7A00'} strokeWidth={on ? 2 : 1} />
                <text x={x} y={y + (y > cy ? 30 : -20)} textAnchor="middle" fontSize={9} fill={on ? '#FFAA00' : '#CBD5E1'}>{label(a)}</text>
              </g>
            )
          })}
        </svg>
        {multi && <p className="text-[11px] text-gray-600 px-3 pb-2">Multiple networks detected — use the subnet tabs above.</p>}
      </div>
      <NodePanel asset={assets.find(a => a.id === sel) ?? null} onPatch={onPatch} />
    </div>
  )
}

function NodePanel({ asset, onPatch }: { asset: Asset | null; onPatch: (id: string, p: Partial<Asset>) => void }) {
  if (!asset) return <div className="card p-4 text-xs text-gray-500 flex items-center justify-center text-center">Select a node to view details and rename it.</div>
  return (
    <div className="card p-4 space-y-3">
      <div>
        <label className="label">Label</label>
        <input defaultValue={asset.label ?? ''} placeholder={asset.hostname || asset.ip_address} onBlur={e => onPatch(asset.id, { label: e.target.value })} className="input mt-1 text-sm" />
      </div>
      <dl className="text-xs space-y-1.5">
        <Row k="IP" v={asset.ip_address} />
        <Row k="Hostname" v={asset.hostname || '—'} />
        <Row k="MAC" v={asset.mac_address || '—'} />
        <Row k="Vendor" v={asset.vendor || '—'} />
      </dl>
      {asset.ports && asset.ports.length > 0 && (
        <div>
          <div className="label mb-1">Open ports</div>
          <div className="flex flex-wrap gap-1">
            {asset.ports.map(p => <span key={p.port} className="badge bg-surface-3 border border-border text-gray-300">{p.port}/{p.service || p.protocol}</span>)}
          </div>
        </div>
      )}
    </div>
  )
}

function Row({ k, v }: { k: string; v: string }) {
  return <div className="flex justify-between"><dt className="text-gray-500">{k}</dt><dd className="text-gray-200 text-right max-w-[150px] truncate">{v}</dd></div>
}

function CmdbTable({ assets, onPatch }: { assets: Asset[]; onPatch: (id: string, p: Partial<Asset>) => void }) {
  const crit = ['', 'High', 'Medium', 'Low']
  const clazz = ['', 'Confidential', 'Internal', 'Public']
  return (
    <div className="card overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-[11px] uppercase tracking-wider text-gray-500 border-b border-border">
            <th className="px-3 py-2 font-medium">IP</th><th className="px-3 py-2 font-medium">Hostname</th><th className="px-3 py-2 font-medium">Vendor</th>
            <th className="px-3 py-2 font-medium">Ports</th><th className="px-3 py-2 font-medium">Owner</th><th className="px-3 py-2 font-medium">Criticality</th><th className="px-3 py-2 font-medium">Classification</th>
          </tr>
        </thead>
        <tbody>
          {assets.map(a => (
            <tr key={a.id} className="border-b border-border/60 hover:bg-white/[0.02]">
              <td className="px-3 py-2 text-gray-200 font-mono text-xs">{a.ip_address}</td>
              <td className="px-3 py-2 text-gray-300">{a.label || a.hostname || '—'}</td>
              <td className="px-3 py-2 text-gray-400 max-w-[140px] truncate">{a.vendor || '—'}</td>
              <td className="px-3 py-2 text-gray-400">{a.ports?.length ?? 0}</td>
              <td className="px-3 py-2"><input defaultValue={a.owner ?? ''} onBlur={e => onPatch(a.id, { owner: e.target.value })} className="input py-1 text-xs w-28" placeholder="—" /></td>
              <td className="px-3 py-2">
                <select defaultValue={a.criticality ?? ''} onChange={e => onPatch(a.id, { criticality: e.target.value })} className="input py-1 text-xs w-24">
                  {crit.map(c => <option key={c} value={c}>{c || '—'}</option>)}
                </select>
              </td>
              <td className="px-3 py-2">
                <select defaultValue={a.classification ?? ''} onChange={e => onPatch(a.id, { classification: e.target.value })} className="input py-1 text-xs w-32">
                  {clazz.map(c => <option key={c} value={c}>{c || '—'}</option>)}
                </select>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="text-[11px] text-gray-600 px-3 py-2">CMDB fields follow ISO 27001 asset inventory. Saved server-side per organization. Re-importing updates discovery data but keeps your CMDB edits.</p>
    </div>
  )
}
