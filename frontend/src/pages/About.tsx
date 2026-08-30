import { Shield, Building2, ScrollText, Lock } from 'lucide-react'

// NOTE: Text in [SQUARE BRACKETS] are placeholders awaiting the real legal /
// company content. Replace them (or send them to me and I'll wire them in).

export function AboutPage() {
  return (
    <div className="flex-1 overflow-y-auto">
      <div className="max-w-3xl mx-auto px-6 py-8 space-y-6">
        {/* Hero */}
        <div className="card-glow p-6">
          <div className="flex items-center gap-3">
            <img src="/logo-mark.svg" alt="harbore" className="w-11 h-11" />
            <div>
              <h1 className="text-xl font-bold text-white">About harbore</h1>
              <p className="text-xs text-gray-500 mt-0.5">Cybersecurity &amp; compliance platform</p>
            </div>
          </div>
          <p className="text-sm text-gray-400 leading-relaxed mt-4">
            harbore is a self-hosted platform for API and web application security. It runs asset discovery,
            TLS/certificate analysis, vulnerability and compliance scanning across many targets in parallel,
            enriches findings, and maps them to frameworks such as PCI DSS, NIS2, DORA and CRA — with
            downloadable reports.
          </p>
        </div>

        {/* Company / Impressum */}
        <section className="card p-6">
          <div className="flex items-center gap-2 mb-4">
            <Building2 className="w-4 h-4 text-accent-amber" />
            <h2 className="text-sm font-semibold text-white">Company &amp; Legal (Impressum)</h2>
          </div>
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-3 text-sm">
            <Row k="Provider" v="CB-Advisory — Cybersecurity and Business Advisory" />
            <Row k="Managing Director / Owner" v="[Full legal name of owner]" />
            <Row k="Registered address" v="[Street, ZIP City, Country]" />
            <Row k="Contact" v="[contact@cb-advisory.eu]" />
            <Row k="Register / Court" v="[Commercial register no. · Register court]" />
            <Row k="VAT ID" v="[VAT identification number]" />
          </dl>
        </section>

        {/* Data Protection / Datenschutz */}
        <section className="card p-6">
          <div className="flex items-center gap-2 mb-4">
            <Lock className="w-4 h-4 text-accent-amber" />
            <h2 className="text-sm font-semibold text-white">Data Protection · Datenschutz (GDPR / DSGVO)</h2>
          </div>
          <div className="space-y-4 text-sm text-gray-400 leading-relaxed">
            <p>
              <span className="text-gray-300 font-medium">Controller.</span> The data controller responsible
              for processing within this application is [CB-Advisory legal entity], [address], contactable at
              [privacy@cb-advisory.eu].
            </p>
            <p>
              <span className="text-gray-300 font-medium">Data Protection Officer.</span> [Name / “not
              required under Art. 37 GDPR” — confirm], reachable at [dpo@cb-advisory.eu].
            </p>
            <p>
              <span className="text-gray-300 font-medium">What we process.</span> Account data (name, email,
              role, hashed password, optional avatar), scan configuration and results you create, and technical
              logs required to operate the service. Scan targets and findings are processed on the legal basis
              of [Art. 6(1)(b) contract / (f) legitimate interest — confirm].
            </p>
            <p>
              <span className="text-gray-300 font-medium">Retention.</span> Data is retained for [retention
              period], after which it is deleted or anonymised. Scans and reports can be deleted by users at any
              time.
            </p>
            <div>
              <span className="text-gray-300 font-medium">Your rights (Art. 15–21 GDPR).</span>
              <ul className="mt-2 space-y-1 list-disc list-inside marker:text-accent-amber/60">
                <li>Access, rectification, and erasure of your personal data</li>
                <li>Restriction of and objection to processing</li>
                <li>Data portability</li>
                <li>Right to lodge a complaint with a supervisory authority ([competent authority])</li>
              </ul>
            </div>
            <p className="text-xs text-gray-600 border-t border-border pt-4">
              This section is a scaffold. The bracketed items must be completed with your legal content before
              production use; harbore does not provide legal advice.
            </p>
          </div>
        </section>

        {/* Footer meta */}
        <div className="flex items-center justify-between text-xs text-gray-600 px-1">
          <span className="flex items-center gap-1.5"><Shield className="w-3.5 h-3.5" /> harbore</span>
          <span className="flex items-center gap-1.5"><ScrollText className="w-3.5 h-3.5" /> Version [x.y.z]</span>
        </div>
      </div>
    </div>
  )
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div>
      <dt className="label mb-0.5">{k}</dt>
      <dd className="text-gray-300">{v}</dd>
    </div>
  )
}
