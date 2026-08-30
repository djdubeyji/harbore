import { type ReactNode } from 'react'
import { sevClass, statusClass } from '../../utils'
import type { Severity, ScanStatus } from '../../types'

// ─── Severity badge ───────────────────────────────────────────────────────────
export function SevBadge({ sev }: { sev: Severity | string }) {
  return <span className={sevClass(sev as Severity)}>{sev}</span>
}

// ─── Status badge ─────────────────────────────────────────────────────────────
export function StatusBadge({ status }: { status: ScanStatus | string }) {
  return <span className={statusClass(status)}>{status}</span>
}

// ─── Progress bar ─────────────────────────────────────────────────────────────
export function ProgressBar({ pct, className = '' }: { pct: number; className?: string }) {
  return (
    <div className={`h-1.5 bg-surface-4 rounded-full overflow-hidden ${className}`}>
      <div
        className="h-full bg-accent-blue rounded-full transition-all duration-500"
        style={{ width: `${Math.min(100, pct)}%` }}
      />
    </div>
  )
}

// ─── Stat card ────────────────────────────────────────────────────────────────
export function StatCard({ label, value, sub, color = '' }: {
  label: string; value: string | number; sub?: string; color?: string
}) {
  return (
    <div className="card px-4 py-3">
      <div className="text-xs text-gray-500 mb-1">{label}</div>
      <div className={`text-2xl font-bold ${color || 'text-white'}`}>{value}</div>
      {sub && <div className="text-xs text-gray-500 mt-0.5">{sub}</div>}
    </div>
  )
}

// ─── Section header ───────────────────────────────────────────────────────────
export function SectionHeader({ title, action }: { title: string; action?: ReactNode }) {
  return (
    <div className="flex items-center justify-between mb-4">
      <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">{title}</h2>
      {action}
    </div>
  )
}

// ─── Empty state ──────────────────────────────────────────────────────────────
export function EmptyState({ icon: Icon, title, sub }: { icon: React.ComponentType<{ className?: string }>; title: string; sub?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <Icon className="w-10 h-10 text-gray-600 mb-3" />
      <div className="text-sm font-medium text-gray-400">{title}</div>
      {sub && <div className="text-xs text-gray-600 mt-1 max-w-xs">{sub}</div>}
    </div>
  )
}

// ─── Loading spinner ──────────────────────────────────────────────────────────
export function Spinner({ className = 'w-5 h-5' }: { className?: string }) {
  return (
    <svg className={`animate-spin text-accent-blue ${className}`} fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  )
}

// ─── Modal ────────────────────────────────────────────────────────────────────
export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-surface-2 border border-border rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] flex flex-col animate-slide-up">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border flex-shrink-0">
          <h3 className="text-sm font-semibold text-white">{title}</h3>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition-colors text-lg leading-none">&times;</button>
        </div>
        <div className="flex-1 overflow-y-auto px-5 py-4">{children}</div>
      </div>
    </div>
  )
}

// ─── Copy button ──────────────────────────────────────────────────────────────
export function CopyButton({ text }: { text: string }) {
  const copy = () => navigator.clipboard.writeText(text)
  return (
    <button onClick={copy} className="text-xs text-gray-500 hover:text-gray-300 transition-colors px-2 py-0.5 rounded border border-border hover:border-border-bright">
      copy
    </button>
  )
}
