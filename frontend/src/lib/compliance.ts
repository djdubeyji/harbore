import { listScans, getFindings } from '../api/client'
import type { Finding, Severity } from '../types'

export type ControlStatus = 'pass' | 'gap' | 'manual'

export interface Control {
  id: string
  title: string
  category: string
  manual?: boolean
  match?: (f: Finding) => boolean
}

export interface ControlResult extends Control {
  status: ControlStatus
  findings: Finding[]
  worst: Severity | null
}

export interface FrameworkResult {
  key: string
  name: string
  controls: ControlResult[]
  summary: { total: number; passed: number; gaps: number; manual: number; score: number }
}

// ── Aggregate real findings across the org's scans ────────────────────────────
export async function aggregateFindings(): Promise<Finding[]> {
  const scans = await listScans()
  const relevant = scans
    .filter(s => s.status === 'completed' || s.status === 'running')
    .slice(0, 25)
  const all: Finding[] = []
  await Promise.all(
    relevant.map(async s => {
      try { const r = await getFindings(s.id); all.push(...(r.findings ?? [])) } catch { /* ignore */ }
    }),
  )
  return all.filter(f => !f.is_false_positive)
}

// ── Matching helpers ──────────────────────────────────────────────────────────
const text = (f: Finding) => `${f.title} ${f.description} ${f.module}`.toLowerCase()
const has = (f: Finding, ...subs: string[]) => subs.some(s => text(f).includes(s.toLowerCase()))
const cwe = (f: Finding, ...ids: string[]) => ids.some(id => (f.cwe_id ?? '').toUpperCase().includes(id.toUpperCase()))
const owasp = (f: Finding, ...ids: string[]) => ids.some(id => (f.owasp_ref ?? '').toUpperCase().includes(id.toUpperCase()))
const anyVuln = (f: Finding) => ['critical', 'high', 'medium', 'low'].includes(f.severity)

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
function worstSeverity(fs: Finding[]): Severity | null {
  if (fs.length === 0) return null
  return fs.reduce((w, f) => (SEV_RANK[f.severity] > SEV_RANK[w] ? f.severity : w), fs[0].severity)
}

// ── Control catalogs ──────────────────────────────────────────────────────────
const PCI: Control[] = [
  { id: '1', title: 'Install and maintain network security controls', category: 'Network', match: f => has(f, 'open port', 'firewall', 'exposed', 'cors', 'unrestricted') },
  { id: '2', title: 'Apply secure configurations to all system components', category: 'Configuration', match: f => owasp(f, 'A05') || has(f, 'default cred', 'misconfig', 'directory listing', 'verbose error', 'security header', 'debug') },
  { id: '3', title: 'Protect stored account data', category: 'Data at rest', manual: true },
  { id: '4', title: 'Protect cardholder data with strong cryptography during transmission', category: 'Cryptography', match: f => cwe(f, 'CWE-319', 'CWE-326', 'CWE-327') || has(f, 'tls 1.0', 'tls 1.1', 'weak cipher', 'ssl', 'certificate', 'plaintext', 'cleartext') },
  { id: '5', title: 'Protect all systems and networks from malicious software', category: 'Anti-malware', manual: true },
  { id: '6', title: 'Develop and maintain secure systems and software', category: 'Secure development', match: f => owasp(f, 'A03', 'A06', 'A08', 'A10') || cwe(f, 'CWE-89', 'CWE-79', 'CWE-918', 'CWE-94', 'CWE-502') || has(f, 'injection', 'xss', 'ssrf', 'deserial', 'rce') },
  { id: '7', title: 'Restrict access to system components by business need to know', category: 'Access control', match: f => owasp(f, 'A01') || cwe(f, 'CWE-284', 'CWE-639') || has(f, 'idor', 'broken access', 'authorization') },
  { id: '8', title: 'Identify users and authenticate access to system components', category: 'Authentication', match: f => owasp(f, 'A07') || cwe(f, 'CWE-287', 'CWE-347', 'CWE-798', 'CWE-521') || has(f, 'jwt', 'password', 'session', 'credential', 'authentication') },
  { id: '9', title: 'Restrict physical access to cardholder data', category: 'Physical', manual: true },
  { id: '10', title: 'Log and monitor all access to system components', category: 'Logging & monitoring', match: f => owasp(f, 'A09') || has(f, 'logging', 'audit trail', 'monitoring') },
  { id: '11', title: 'Test security of systems and networks regularly', category: 'Testing', match: () => false },
  { id: '12', title: 'Support information security with organizational policies', category: 'Governance', manual: true },
]

const NIS2: Control[] = [
  { id: 'a', title: 'Risk analysis and information system security policies', category: 'Governance', manual: true },
  { id: 'b', title: 'Incident handling', category: 'Operations', manual: true },
  { id: 'c', title: 'Business continuity and crisis management', category: 'Resilience', manual: true },
  { id: 'd', title: 'Supply chain security', category: 'Third party', match: f => owasp(f, 'A06') || has(f, 'outdated', 'vulnerable component', 'dependency', 'known cve', 'end-of-life') },
  { id: 'e', title: 'Security in acquisition, development and maintenance (vulnerability handling & disclosure)', category: 'Secure development', match: anyVuln },
  { id: 'f', title: 'Policies to assess the effectiveness of measures', category: 'Assurance', manual: true },
  { id: 'g', title: 'Basic cyber hygiene practices and security training', category: 'People', manual: true },
  { id: 'h', title: 'Cryptography and, where appropriate, encryption', category: 'Cryptography', match: f => cwe(f, 'CWE-319', 'CWE-326', 'CWE-327') || has(f, 'tls', 'ssl', 'weak cipher', 'certificate', 'cleartext') },
  { id: 'i', title: 'Human resources security, access control and asset management', category: 'Access control', match: f => owasp(f, 'A01', 'A07') || has(f, 'access', 'authentication', 'authorization', 'session') },
  { id: 'j', title: 'Multi-factor authentication and secured communications', category: 'Access control', match: f => owasp(f, 'A07') || has(f, 'mfa', '2fa', 'jwt', 'session', 'tls') },
]

const DORA: Control[] = [
  { id: '1', title: 'ICT risk management framework', category: 'Risk management', match: anyVuln },
  { id: '2', title: 'ICT-related incident management, classification and reporting', category: 'Incidents', manual: true },
  { id: '3', title: 'Digital operational resilience testing', category: 'Testing', match: () => false },
  { id: '4', title: 'Management of ICT third-party risk', category: 'Third party', match: f => owasp(f, 'A06') || has(f, 'outdated', 'vulnerable component', 'dependency', 'known cve') },
  { id: '5', title: 'Information-sharing arrangements', category: 'Intelligence', manual: true },
  { id: '6', title: 'Protection and prevention (secure configuration, encryption)', category: 'Protection', match: f => owasp(f, 'A05') || has(f, 'tls', 'ssl', 'misconfig', 'security header', 'weak cipher') },
]

const CRA: Control[] = [
  { id: '1', title: 'Secure by design and secure default configuration', category: 'Design', match: f => owasp(f, 'A05') || has(f, 'default cred', 'misconfig', 'security header', 'directory listing') },
  { id: '2', title: 'Delivered without known exploitable vulnerabilities', category: 'Vulnerabilities', match: f => f.severity === 'critical' || f.severity === 'high' },
  { id: '3', title: 'Protect confidentiality (encryption of data in transit/at rest)', category: 'Confidentiality', match: f => cwe(f, 'CWE-319', 'CWE-326', 'CWE-327') || has(f, 'tls', 'ssl', 'cleartext', 'plaintext') },
  { id: '4', title: 'Protect integrity of data, commands and configuration', category: 'Integrity', match: f => owasp(f, 'A03', 'A08') || cwe(f, 'CWE-89', 'CWE-79', 'CWE-502') || has(f, 'injection', 'xss', 'tamper', 'deserial') },
  { id: '5', title: 'Minimize attack surface and exposure', category: 'Attack surface', match: f => has(f, 'open port', 'exposed', 'unnecessary', 'unrestricted', 'ssrf') },
  { id: '6', title: 'Vulnerability handling process and coordinated disclosure', category: 'Process', manual: true },
  { id: '7', title: 'Provide security updates for the expected product lifetime', category: 'Maintenance', manual: true },
]

const CATALOGS: Record<string, { name: string; controls: Control[] }> = {
  pci: { name: 'PCI DSS 4.0.1', controls: PCI },
  nis2: { name: 'NIS2 Directive (Art. 21)', controls: NIS2 },
  dora: { name: 'DORA', controls: DORA },
  cra: { name: 'Cyber Resilience Act', controls: CRA },
}

export function computeFramework(key: string, findings: Finding[]): FrameworkResult {
  const cat = CATALOGS[key]
  const controls: ControlResult[] = cat.controls.map(c => {
    if (c.manual) return { ...c, status: 'manual', findings: [], worst: null }
    const matched = c.match ? findings.filter(c.match) : []
    return { ...c, status: matched.length ? 'gap' : 'pass', findings: matched, worst: worstSeverity(matched) }
  })
  const assessable = controls.filter(c => c.status !== 'manual')
  const passed = assessable.filter(c => c.status === 'pass').length
  const gaps = assessable.filter(c => c.status === 'gap').length
  const manual = controls.filter(c => c.status === 'manual').length
  const score = assessable.length ? Math.round((passed / assessable.length) * 100) : 0
  return { key, name: cat.name, controls, summary: { total: controls.length, passed, gaps, manual, score } }
}

// ── Downloadable HTML report (print-to-PDF ready) ─────────────────────────────
export function downloadReport(res: FrameworkResult, orgName: string) {
  const esc = (s: string) => s.replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c] as string))
  const badge = (c: ControlResult) =>
    c.status === 'manual' ? '<span class="b manual">Manual attestation</span>'
      : c.status === 'pass' ? '<span class="b pass">No findings</span>'
        : `<span class="b gap">${c.findings.length} finding(s) · ${c.worst}</span>`
  const rows = res.controls.map(c => `
    <tr>
      <td class="id">${esc(c.id)}</td>
      <td><div class="ct">${esc(c.title)}</div><div class="cat">${esc(c.category)}</div></td>
      <td>${badge(c)}</td>
      <td>${c.findings.slice(0, 8).map(f => `<div class="f">${esc(f.title)} <span class="sev ${f.severity}">${f.severity}</span></div>`).join('') || '<span class="dim">—</span>'}</td>
    </tr>`).join('')
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${esc(res.name)} — ${esc(orgName)}</title>
<style>
  body{font-family:-apple-system,Segoe UI,system-ui,sans-serif;color:#0f172a;margin:40px;font-size:13px}
  h1{font-size:22px;margin:0 0 4px}.sub{color:#64748b;margin-bottom:24px}
  .cards{display:flex;gap:12px;margin-bottom:24px}
  .card{flex:1;border:1px solid #e2e8f0;border-radius:10px;padding:14px}
  .card .n{font-size:26px;font-weight:800}.card .k{font-size:11px;color:#64748b;text-transform:uppercase}
  table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top}
  th{font-size:10px;text-transform:uppercase;color:#64748b}
  .id{font-weight:700;color:#b45309}.ct{font-weight:600}.cat{font-size:11px;color:#94a3b8}
  .b{font-size:11px;font-weight:700;padding:2px 8px;border-radius:5px;white-space:nowrap}
  .b.pass{background:#dcfce7;color:#166534}.b.gap{background:#fee2e2;color:#991b1b}.b.manual{background:#fef3c7;color:#92400e}
  .f{font-size:12px;margin-bottom:3px}.sev{font-size:10px;padding:0 5px;border-radius:4px;text-transform:uppercase}
  .sev.critical{background:#fecaca;color:#7f1d1d}.sev.high{background:#fed7aa;color:#7c2d12}.sev.medium{background:#fef08a;color:#713f12}.sev.low{background:#bae6fd;color:#0c4a6e}.sev.info{background:#e2e8f0;color:#334155}
  .dim{color:#cbd5e1}.foot{margin-top:24px;color:#94a3b8;font-size:11px}
</style></head><body>
  <h1>${esc(res.name)} — Compliance Report</h1>
  <div class="sub">${esc(orgName)} · generated ${new Date().toLocaleString()}</div>
  <div class="cards">
    <div class="card"><div class="k">Readiness (assessable)</div><div class="n">${res.summary.score}%</div></div>
    <div class="card"><div class="k">No findings</div><div class="n" style="color:#16a34a">${res.summary.passed}</div></div>
    <div class="card"><div class="k">Gaps</div><div class="n" style="color:#dc2626">${res.summary.gaps}</div></div>
    <div class="card"><div class="k">Manual attestation</div><div class="n" style="color:#d97706">${res.summary.manual}</div></div>
  </div>
  <table><thead><tr><th>#</th><th>Control</th><th>Status</th><th>Mapped findings</th></tr></thead><tbody>${rows}</tbody></table>
  <div class="foot">Generated by harbore. Technical controls are mapped automatically from scan findings; manual-attestation controls require organizational evidence. This report is not a formal certification.</div>
</body></html>`
  const blob = new Blob([html], { type: 'text/html' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${res.key}-compliance-report.html`
  a.click()
  URL.revokeObjectURL(url)
}
