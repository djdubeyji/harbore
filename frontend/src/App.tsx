import { useState } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './hooks/useAuth'
import { OrgProvider, useOrg } from './hooks/useOrg'
import { Sidebar } from './components/layout/Sidebar'
import { TopBar } from './components/layout/TopBar'
import { LoginPage }      from './pages/Login'
import { Landing }        from './pages/Landing'
import { DashboardPage }  from './pages/Dashboard'
import { NewScanPage }    from './pages/NewScan'
import { ScanDetailPage } from './pages/ScanDetail'
import { ConsolePage }    from './pages/Console'
import { AboutPage }      from './pages/About'
import { SettingsPage }   from './pages/Settings'
import { AssetDiscoveryPage } from './pages/AssetDiscovery'
import { TlsPage } from './pages/Tls'
import { PciPage } from './pages/Pci'
import { CompliancePage } from './pages/Compliance'
import { Spinner } from './components/ui'

function ProtectedLayout() {
  const { user, loading } = useAuth()
  const { loading: orgLoading } = useOrg()
  const [collapsed, setCollapsed] = useState(false)

  const scrollToTop = () => {
    const main = document.getElementById('app-main')
    main?.scrollTo({ top: 0, behavior: 'smooth' })
    main?.querySelector('.overflow-y-auto')?.scrollTo({ top: 0, behavior: 'smooth' })
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  if (loading) return (
    <div className="min-h-screen bg-surface-0 flex items-center justify-center">
      <Spinner className="w-8 h-8" />
    </div>
  )
  if (!user) return <Navigate to="/landing" replace />
  if (orgLoading) return (
    <div className="min-h-screen bg-surface-0 flex items-center justify-center">
      <Spinner className="w-8 h-8" />
    </div>
  )

  return (
    <div className="min-h-screen flex flex-col bg-surface-0">
      <TopBar collapsed={collapsed} onToggle={() => setCollapsed(c => !c)} />

      <div className="flex flex-1 min-h-0">
        <Sidebar collapsed={collapsed} />

        <main id="app-main" className="flex-1 flex flex-col overflow-hidden relative">
          <Routes>
            <Route path="/"              element={<DashboardPage />} />
            <Route path="/scans"         element={<DashboardPage />} />
            <Route path="/scans/new"     element={<NewScanPage />} />
            <Route path="/scans/:id"     element={<ScanDetailPage />} />
            <Route path="/console"       element={<ConsolePage />} />
            <Route path="/assets"        element={<AssetDiscoveryPage />} />
            <Route path="/tls"           element={<TlsPage />} />
            <Route path="/pci"           element={<PciPage />} />
            <Route path="/compliance"    element={<CompliancePage />} />
            <Route path="/about"         element={<AboutPage />} />
            <Route path="/projects"      element={<div className="flex-1 flex items-center justify-center text-gray-600 text-sm">Projects — coming soon</div>} />
            <Route path="/settings"      element={<SettingsPage />} />
            <Route path="*"              element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>

      {/* Bottom-center shield — silent scroll-to-top (no label / easter egg) */}
      <button
        onClick={scrollToTop}
        aria-hidden
        tabIndex={-1}
        className="fixed bottom-4 left-1/2 -translate-x-1/2 z-40 opacity-40 hover:opacity-100
                   hover:-translate-y-0.5 transition-all duration-300 cursor-pointer"
      >
        <img src="/logo-mark.svg" alt="" className="w-8 h-8" draggable={false} />
      </button>
    </div>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/landing" element={<Landing />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/*"     element={<OrgProvider><ProtectedLayout /></OrgProvider>} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
