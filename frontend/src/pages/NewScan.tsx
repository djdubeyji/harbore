import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ChevronRight, ChevronLeft, Plus, X } from 'lucide-react'
import { createScan, startScan } from '../api/client'
import { ALL_MODULES, MODULE_LABELS } from '../utils'
import type { TargetType, CreateScanRequest } from '../types'

const STEPS = ['Targets', 'Auth', 'Modules', 'Settings', 'Review']

const TARGET_TYPES: { value: TargetType; label: string; hint: string }[] = [
  { value: 'url_list',  label: 'URL List',      hint: 'One URL per line' },
  { value: 'openapi',   label: 'OpenAPI Spec',  hint: 'Paste spec JSON/YAML or URL' },
  { value: 'postman',   label: 'Postman',        hint: 'Collection JSON' },
  { value: 'graphql',   label: 'GraphQL',        hint: 'Schema or endpoint URL' },
  { value: 'har',       label: 'HAR File',       hint: 'Browser traffic capture path' },
  { value: 'single_url',label: 'Single URL',     hint: 'One target URL' },
]

const DEFAULT_PROJECT = '00000000-0000-0000-0000-000000000000'

export function NewScanPage() {
  const navigate = useNavigate()
  const [step, setStep]       = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState('')

  // Form state
  const [name, setName]             = useState('')
  const [targetType, setTargetType] = useState<TargetType>('url_list')
  const [targetsRaw, setTargetsRaw] = useState('')
  const [bearer, setBearer]         = useState('')
  const [extraHeaders, setExtraHeaders] = useState<[string,string][]>([])
  const [selectedModules, setSelectedModules] = useState<string[]>(['asset','cert','vuln','crawler','auth'])
  const [containerLimit, setContainerLimit]   = useState(5)
  const [maxRetries, setMaxRetries]           = useState(3)
  const [nuclei, setNuclei]                   = useState(false)
  const [autoStart, setAutoStart]             = useState(true)

  const targets = targetsRaw.split('\n').map(t => t.trim()).filter(Boolean)

  const toggleModule = (m: string) =>
    setSelectedModules(prev => prev.includes(m) ? prev.filter(x => x !== m) : [...prev, m])

  const addHeader = () => setExtraHeaders(h => [...h, ['', '']])
  const setHeader = (i: number, k: 'key' | 'v', val: string) =>
    setExtraHeaders(h => h.map((pair, idx) => idx === i ? (k === 'key' ? [val, pair[1]] : [pair[0], val]) : pair))
  const removeHeader = (i: number) => setExtraHeaders(h => h.filter((_, idx) => idx !== i))

  const submit = async () => {
    setError('')
    setLoading(true)
    try {
      const headers: Record<string, string> = {}
      extraHeaders.forEach(([k, v]) => { if (k) headers[k] = v })

      const req: CreateScanRequest = {
        project_id:      DEFAULT_PROJECT,
        name,
        target_type:     targetType,
        modules:         selectedModules,
        container_limit: containerLimit,
        max_retries:     maxRetries,
        config: {
          targets,
          auth: { headers, cookies: {}, bearer },
          nuclei_enabled: nuclei,
          module_config: {},
        },
      }
      const scan = await createScan(req)
      if (autoStart) await startScan(scan.id)
      navigate(`/scans/${scan.id}`)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to create scan')
    } finally {
      setLoading(false)
    }
  }

  const canNext = () => {
    if (step === 0) return name.trim() && targets.length > 0
    if (step === 2) return selectedModules.length > 0
    return true
  }

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="max-w-3xl mx-auto px-6 py-6">
        <h1 className="text-xl font-bold text-white mb-6">New Scan</h1>

        {/* Step indicator */}
        <div className="flex items-center gap-0 mb-8">
          {STEPS.map((s, i) => (
            <div key={s} className="flex items-center">
              <button
                onClick={() => i < step && setStep(i)}
                className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-full transition-colors ${
                  i === step ? 'bg-accent-blue text-white' :
                  i < step   ? 'text-green-400 cursor-pointer hover:text-green-300' :
                  'text-gray-600 cursor-default'
                }`}
              >
                <span className={`w-4 h-4 rounded-full flex items-center justify-center text-[10px] font-bold border ${
                  i === step ? 'border-white/30 bg-white/20' :
                  i < step   ? 'border-green-400/30 bg-green-400/20' :
                  'border-gray-600 bg-transparent'
                }`}>{i < step ? '✓' : i + 1}</span>
                {s}
              </button>
              {i < STEPS.length - 1 && <div className="w-6 h-px bg-border mx-1" />}
            </div>
          ))}
        </div>

        <div className="card p-6">
          {/* Step 0: Targets */}
          {step === 0 && (
            <div className="space-y-5">
              <div>
                <label className="label block mb-1.5">Scan name</label>
                <input className="input" value={name} onChange={e => setName(e.target.value)} placeholder="Q3 API security audit" autoFocus />
              </div>
              <div>
                <label className="label block mb-2">Target type</label>
                <div className="grid grid-cols-3 gap-2">
                  {TARGET_TYPES.map(t => (
                    <button
                      key={t.value}
                      onClick={() => setTargetType(t.value)}
                      className={`p-3 rounded-lg border text-left transition-colors ${
                        targetType === t.value
                          ? 'border-accent-blue bg-accent-blue/10 text-white'
                          : 'border-border bg-surface-3 text-gray-400 hover:border-border-bright hover:text-gray-300'
                      }`}
                    >
                      <div className="text-sm font-medium">{t.label}</div>
                      <div className="text-[11px] mt-0.5 opacity-60">{t.hint}</div>
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="label block mb-1.5">
                  Targets <span className="text-gray-600 normal-case tracking-normal font-normal">({targets.length} parsed)</span>
                </label>
                <textarea
                  className="input resize-none font-mono"
                  rows={8}
                  value={targetsRaw}
                  onChange={e => setTargetsRaw(e.target.value)}
                  placeholder={targetType === 'url_list'
                    ? 'https://api.example.com/v1/users\nhttps://api.example.com/v1/payments\nhttps://api.example.com/v1/orders'
                    : 'https://api.example.com/openapi.json'}
                />
              </div>
            </div>
          )}

          {/* Step 1: Auth */}
          {step === 1 && (
            <div className="space-y-5">
              <div>
                <label className="label block mb-1.5">Bearer token</label>
                <input className="input font-mono" value={bearer} onChange={e => setBearer(e.target.value)} placeholder="eyJhbGciOiJIUzI1NiIs..." />
                <p className="text-xs text-gray-600 mt-1">Used in Authorization: Bearer header for all requests</p>
              </div>
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="label">Custom headers</label>
                  <button className="btn-ghost text-xs py-1" onClick={addHeader}>
                    <Plus className="w-3 h-3" /> Add header
                  </button>
                </div>
                <div className="space-y-2">
                  {extraHeaders.map(([k, v], i) => (
                    <div key={i} className="flex gap-2 items-center">
                      <input className="input flex-1" value={k} onChange={e => setHeader(i, 'key', e.target.value)} placeholder="Header-Name" />
                      <input className="input flex-1" value={v} onChange={e => setHeader(i, 'v', e.target.value)} placeholder="value" />
                      <button onClick={() => removeHeader(i)} className="text-gray-600 hover:text-red-400 transition-colors"><X className="w-4 h-4" /></button>
                    </div>
                  ))}
                  {extraHeaders.length === 0 && <p className="text-xs text-gray-600">No custom headers. Cookie-based auth? Add Cookie header above.</p>}
                </div>
              </div>
            </div>
          )}

          {/* Step 2: Modules */}
          {step === 2 && (
            <div>
              <p className="text-xs text-gray-500 mb-4">Select which scan modules to run. Heavier modules (fuzzer) take longer but find more issues.</p>
              <div className="grid grid-cols-3 gap-2">
                {ALL_MODULES.map(m => {
                  const on = selectedModules.includes(m)
                  const weights: Record<string, string> = { fuzzer: 'Heavy', vuln: 'Heavy', auth: 'Heavy', pci: 'Medium', crawler: 'Medium', asset: 'Light', cert: 'Light', passive: 'Light', compliance: 'Light' }
                  return (
                    <button
                      key={m}
                      onClick={() => toggleModule(m)}
                      className={`p-3 rounded-lg border text-left transition-colors ${
                        on ? 'border-accent-blue bg-accent-blue/10' : 'border-border bg-surface-3 hover:border-border-bright'
                      }`}
                    >
                      <div className={`text-sm font-medium ${on ? 'text-white' : 'text-gray-400'}`}>{MODULE_LABELS[m]}</div>
                      <div className={`text-[11px] mt-0.5 ${weights[m] === 'Heavy' ? 'text-red-400/60' : weights[m] === 'Medium' ? 'text-yellow-400/60' : 'text-green-400/60'}`}>{weights[m]}</div>
                    </button>
                  )
                })}
                <button
                  onClick={() => setNuclei(!nuclei)}
                  className={`p-3 rounded-lg border text-left transition-colors ${
                    nuclei ? 'border-accent-blue bg-accent-blue/10' : 'border-border bg-surface-3 hover:border-border-bright'
                  }`}
                >
                  <div className={`text-sm font-medium ${nuclei ? 'text-white' : 'text-gray-400'}`}>Nuclei</div>
                  <div className="text-[11px] mt-0.5 text-yellow-400/60">Templates</div>
                </button>
              </div>
            </div>
          )}

          {/* Step 3: Settings */}
          {step === 3 && (
            <div className="space-y-5">
              <div>
                <label className="label block mb-1.5">Container limit <span className="text-gray-600 normal-case tracking-normal font-normal">— max parallel workers</span></label>
                <div className="flex items-center gap-3">
                  <input type="range" min={1} max={50} value={containerLimit} onChange={e => setContainerLimit(+e.target.value)} className="flex-1 accent-blue-500" />
                  <span className="text-sm font-mono text-accent-blue w-6 text-right">{containerLimit}</span>
                </div>
                <p className="text-xs text-gray-600 mt-1">{containerLimit} containers × up to {containerLimit * 2}+ APIs/min estimated throughput</p>
              </div>
              <div>
                <label className="label block mb-1.5">Max retries per job</label>
                <div className="flex gap-2">
                  {[1,2,3,5].map(n => (
                    <button key={n} onClick={() => setMaxRetries(n)}
                      className={`px-4 py-1.5 rounded border text-sm transition-colors ${maxRetries === n ? 'border-accent-blue bg-accent-blue/15 text-accent-blue' : 'border-border text-gray-500 hover:border-border-bright'}`}>
                      {n}
                    </button>
                  ))}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <input type="checkbox" id="autostart" checked={autoStart} onChange={e => setAutoStart(e.target.checked)} className="rounded border-border" />
                <label htmlFor="autostart" className="text-sm text-gray-400 cursor-pointer">Start scan immediately after creation</label>
              </div>
            </div>
          )}

          {/* Step 4: Review */}
          {step === 4 && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                {[
                  ['Name', name],
                  ['Type', targetType],
                  ['Targets', `${targets.length} URL${targets.length !== 1 ? 's' : ''}`],
                  ['Auth', bearer ? 'Bearer token configured' : 'No authentication'],
                  ['Modules', selectedModules.join(', ')],
                  ['Containers', String(containerLimit)],
                  ['Max retries', String(maxRetries)],
                  ['Nuclei', nuclei ? 'Enabled' : 'Disabled'],
                  ['Auto-start', autoStart ? 'Yes' : 'No'],
                ].map(([k, v]) => (
                  <div key={k} className="bg-surface-3 rounded-lg px-3 py-2">
                    <div className="text-xs text-gray-500 mb-0.5">{k}</div>
                    <div className="text-gray-200 font-medium">{v}</div>
                  </div>
                ))}
              </div>
              {targets.length > 0 && (
                <div>
                  <div className="label mb-1.5">Targets preview</div>
                  <div className="code-block max-h-32 overflow-y-auto">
                    {targets.slice(0, 10).map((t, i) => <div key={i} className="text-gray-400">{t}</div>)}
                    {targets.length > 10 && <div className="text-gray-600">…and {targets.length - 10} more</div>}
                  </div>
                </div>
              )}
              {error && <div className="text-xs text-red-400 bg-red-400/10 border border-red-400/20 rounded px-3 py-2">{error}</div>}
            </div>
          )}
        </div>

        {/* Navigation */}
        <div className="flex items-center justify-between mt-4">
          <button
            className="btn-ghost"
            onClick={() => step === 0 ? navigate('/') : setStep(s => s - 1)}
          >
            <ChevronLeft className="w-4 h-4" />
            {step === 0 ? 'Cancel' : 'Back'}
          </button>
          {step < STEPS.length - 1 ? (
            <button className="btn-primary" onClick={() => setStep(s => s + 1)} disabled={!canNext()}>
              Next <ChevronRight className="w-4 h-4" />
            </button>
          ) : (
            <button className="btn-primary" onClick={submit} disabled={loading}>
              {loading ? 'Creating…' : (autoStart ? 'Create & Start Scan' : 'Create Scan')}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
