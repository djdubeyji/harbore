import { useState } from 'react'
import { X, FileText } from 'lucide-react'
import { generateGovernanceReport } from '../api/client'

interface Sig { name: string; email: string; title: string; date: string }
const emptySig = (): Sig => ({ name: '', email: '', title: '', date: '' })

export function GovReportModal({ scanId, scanName, onClose }: { scanId: string; scanName: string; onClose: () => void }) {
  const [f, setF] = useState({
    document_title: `${scanName} — Security Assessment Report`,
    subtitle: '',
    description: '',
    version: '1.0',
    effective_date: new Date().toISOString().slice(0, 10),
    status: 'Draft',
    owner: '',
  })
  const [prepared, setPrepared] = useState<Sig>(emptySig())
  const [reviewed, setReviewed] = useState<Sig>(emptySig())
  const [approved, setApproved] = useState<Sig>(emptySig())
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value })

  const submit = async () => {
    setBusy(true); setErr(null)
    try {
      await generateGovernanceReport(scanId, { ...f, prepared, reviewed, approved,
        amendment_context: f.status, amendment_revision: `Version ${f.version}`, amendment_date: f.effective_date, amendment_by: prepared.name })
      onClose()
    } catch (e) { setErr(e instanceof Error ? e.message : 'Failed') }
    finally { setBusy(false) }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4" onClick={onClose}>
      <div className="card w-full max-w-2xl max-h-[88vh] overflow-y-auto p-6" onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-2 mb-4">
          <FileText className="w-4 h-4 text-accent-amber" />
          <h2 className="text-sm font-semibold text-white">Create ISMS Report (DOCX)</h2>
          <button onClick={onClose} className="ml-auto p-1 rounded hover:bg-white/5 text-gray-400"><X className="w-4 h-4" /></button>
        </div>

        <div className="grid sm:grid-cols-2 gap-3">
          <Field label="Document title" className="sm:col-span-2"><input value={f.document_title} onChange={set('document_title')} className="input" /></Field>
          <Field label="Subtitle" className="sm:col-span-2"><input value={f.subtitle} onChange={set('subtitle')} className="input" placeholder="e.g. External assessment of app.example.com" /></Field>
          <Field label="Description" className="sm:col-span-2"><textarea value={f.description} onChange={set('description')} className="input h-16 resize-y" /></Field>
          <Field label="Version"><input value={f.version} onChange={set('version')} className="input" /></Field>
          <Field label="Effective date"><input type="date" value={f.effective_date} onChange={set('effective_date')} className="input" /></Field>
          <Field label="Status">
            <select value={f.status} onChange={set('status')} className="input">
              {['Draft', 'Final', 'Revision'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </Field>
          <Field label="Document owner"><input value={f.owner} onChange={set('owner')} className="input" /></Field>
        </div>

        <div className="mt-5 space-y-3">
          <div className="label">Signatories</div>
          <SigRow label="Prepared by" sig={prepared} set={setPrepared} />
          <SigRow label="Reviewed by" sig={reviewed} set={setReviewed} />
          <SigRow label="Approved by" sig={approved} set={setApproved} />
        </div>

        <div className="flex items-center gap-3 mt-6">
          <button onClick={submit} disabled={busy || !f.document_title} className="btn-primary text-sm disabled:opacity-50">
            {busy ? 'Generating…' : 'Generate & download'}
          </button>
          <button onClick={onClose} className="btn-ghost text-sm">Cancel</button>
          {err && <span className="text-xs text-[#FF6B7D]">{err}</span>}
        </div>
      </div>
    </div>
  )
}

function Field({ label, children, className }: { label: string; children: React.ReactNode; className?: string }) {
  return <div className={className}><label className="label">{label}</label><div className="mt-1">{children}</div></div>
}

function SigRow({ label, sig, set }: { label: string; sig: Sig; set: (s: Sig) => void }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 items-center">
      <span className="text-xs text-gray-400">{label}</span>
      <input value={sig.name} onChange={e => set({ ...sig, name: e.target.value })} placeholder="Name" className="input py-1.5 text-xs" />
      <input value={sig.email} onChange={e => set({ ...sig, email: e.target.value })} placeholder="Email" className="input py-1.5 text-xs" />
      <input value={sig.title} onChange={e => set({ ...sig, title: e.target.value })} placeholder="Title" className="input py-1.5 text-xs" />
    </div>
  )
}
