import { useEffect, useState, useCallback } from 'react'
import { CreditCard, RotateCw } from 'lucide-react'
import { aggregateFindings, computeFramework, type FrameworkResult } from '../lib/compliance'
import { ComplianceView } from '../components/ComplianceView'
import { useOrg } from '../hooks/useOrg'
import { listScans, getScan, retestScan, reconcileRetest } from '../api/client'

export function PciPage() {
  const { activeOrg } = useOrg()
  const [result, setResult] = useState<FrameworkResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [retesting, setRetesting] = useState(false)
  const [retestMsg, setRetestMsg] = useState('')

  const run = useCallback(async () => {
    setLoading(true)
    try {
      const findings = await aggregateFindings()
      // Remediated findings no longer count as control gaps.
      const open = findings.filter(f => f.status !== 'fixed')
      setResult(computeFramework('pci', open))
    } finally { setLoading(false) }
  }, [])

  useEffect(() => { run() }, [run])

  // Retest the most recent completed scan, reconcile, then recompute PCI posture.
  const retestLatest = async () => {
    setRetesting(true); setRetestMsg('Finding latest scan\u2026')
    try {
      const scans = await listScans()
      const latest = scans.filter(s => s.status === 'completed')
        .sort((a, b) => (b.started_at ?? '').localeCompare(a.started_at ?? ''))[0]
      if (!latest) { setRetestMsg('No completed scan to retest'); setRetesting(false); return }
      setRetestMsg('Retest queued\u2026')
      const r = await retestScan(latest.id)
      await new Promise<void>((resolve) => {
        const iv = setInterval(async () => {
          try {
            const rs = await getScan(r.retest_scan_id)
            if (rs.status === 'completed') {
              clearInterval(iv)
              const res = await reconcileRetest(latest.id, r.retest_scan_id)
              setRetestMsg(`Retest complete \u2014 ${res.fixed} fixed \u00b7 ${res.still_open} still open`)
              resolve()
            } else if (rs.status === 'failed') { clearInterval(iv); setRetestMsg('Retest failed'); resolve() }
            else setRetestMsg(`Retesting\u2026 (${rs.status})`)
          } catch { /* keep polling */ }
        }, 4000)
      })
      await run()
    } catch { setRetestMsg('Retest failed') }
    finally { setRetesting(false) }
  }

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="max-w-4xl mx-auto px-6 py-8">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-lg bg-accent-amber/15 border border-border flex items-center justify-center">
            <CreditCard className="w-5 h-5 text-accent-amber" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">PCI DSS 4.0.1</h1>
            <p className="text-xs text-gray-500 mt-0.5">The 12 requirements, mapped from your scan findings</p>
          </div>
          <button onClick={retestLatest} disabled={retesting} className="btn-ghost text-sm ml-auto">
            <RotateCw className={`w-3.5 h-3.5 ${retesting ? 'animate-spin' : ''}`} /> {retesting ? 'Retesting\u2026' : 'Retest latest scan'}
          </button>
        </div>
        {retestMsg && <div className="text-xs text-gray-400 mb-3">{retestMsg}</div>}
        <ComplianceView result={result} orgName={activeOrg?.name ?? 'Organization'} loading={loading} onRecompute={run} />
      </div>
    </div>
  )
}
