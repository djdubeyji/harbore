import { useEffect, useState, useCallback } from 'react'
import { ClipboardCheck } from 'lucide-react'
import { aggregateFindings, computeFramework, type FrameworkResult } from '../lib/compliance'
import { ComplianceView } from '../components/ComplianceView'
import { useOrg } from '../hooks/useOrg'
import type { Finding } from '../types'

const TABS: { key: string; label: string }[] = [
  { key: 'nis2', label: 'NIS2' },
  { key: 'dora', label: 'DORA' },
  { key: 'cra', label: 'CRA' },
]

export function CompliancePage() {
  const { activeOrg } = useOrg()
  const [tab, setTab] = useState('nis2')
  const [findings, setFindings] = useState<Finding[] | null>(null)
  const [result, setResult] = useState<FrameworkResult | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const f = await aggregateFindings()
      const open = f.filter(x => x.status !== 'fixed')
      setFindings(open)
      setResult(computeFramework(tab, open))
    } finally { setLoading(false) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => { load() }, [load])
  // Recompute instantly when switching tabs (no refetch).
  useEffect(() => { if (findings) setResult(computeFramework(tab, findings)) }, [tab, findings])

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="max-w-4xl mx-auto px-6 py-8">
        <div className="flex items-center gap-3 mb-5">
          <div className="w-10 h-10 rounded-lg bg-accent-amber/15 border border-border flex items-center justify-center">
            <ClipboardCheck className="w-5 h-5 text-accent-amber" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Compliance</h1>
            <p className="text-xs text-gray-500 mt-0.5">EU frameworks mapped from your scan findings, with per-framework reports</p>
          </div>
        </div>

        <div className="flex gap-1 mb-5 border-b border-border">
          {TABS.map(t => (
            <button key={t.key} onClick={() => setTab(t.key)}
              className={`px-4 py-2 text-sm -mb-px border-b-2 transition-colors ${tab === t.key ? 'border-accent-amber text-accent-amber' : 'border-transparent text-gray-400 hover:text-gray-200'}`}>
              {t.label}
            </button>
          ))}
        </div>

        <ComplianceView result={result} orgName={activeOrg?.name ?? 'Organization'} loading={loading} onRecompute={load} />
      </div>
    </div>
  )
}
