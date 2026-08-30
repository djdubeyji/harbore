import { type Severity } from '../types'

export function sevClass(s: Severity | string) {
  return `sev-${s}`
}

export function statusClass(s: string) {
  return `status-${s}`
}

export function cvssColor(score?: number): string {
  if (!score) return 'text-gray-400'
  if (score >= 9.0) return 'text-red-400'
  if (score >= 7.0) return 'text-orange-400'
  if (score >= 4.0) return 'text-yellow-400'
  return 'text-blue-400'
}

export function formatDate(d: string): string {
  return new Date(d).toLocaleString('en-US', {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
  })
}

export function formatDuration(start?: string, end?: string): string {
  if (!start) return '—'
  const s = new Date(start)
  const e = end ? new Date(end) : new Date()
  const ms = e.getTime() - s.getTime()
  const mins = Math.floor(ms / 60000)
  const secs = Math.floor((ms % 60000) / 1000)
  return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`
}

export function progressPct(completed: number, failed: number, total: number): number {
  if (!total) return 0
  return Math.round(((completed + failed) / total) * 100)
}

export const MODULE_LABELS: Record<string, string> = {
  asset:      'Asset Discovery',
  cert:       'TLS/Cert',
  vuln:       'Vuln Scanner',
  crawler:    'API Crawler',
  auth:       'Auth & AuthZ',
  fuzzer:     'Active Fuzzer',
  pci:        'PCI DSS',
  passive:    'Passive Analysis',
  compliance: 'Compliance',
}

export const MODULE_COLORS: Record<string, string> = {
  asset:      'text-blue-400',
  cert:       'text-purple-400',
  vuln:       'text-red-400',
  crawler:    'text-green-400',
  auth:       'text-orange-400',
  fuzzer:     'text-red-400',
  pci:        'text-pink-400',
  passive:    'text-cyan-400',
  compliance: 'text-yellow-400',
}

export const ALL_MODULES = Object.keys(MODULE_LABELS)
