import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Menu, X, Search, Bell, ChevronDown, Building2, Settings, Info, LogOut, Check, Plus } from 'lucide-react'
import { useAuth } from '../../hooks/useAuth'
import { useOrg } from '../../hooks/useOrg'

export function TopBar({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  const { user, logout } = useAuth()
  const { orgs, activeOrg, setActiveOrg } = useOrg()
  const navigate = useNavigate()

  const [orgOpen, setOrgOpen] = useState(false)
  const [userOpen, setUserOpen] = useState(false)

  const ref = useRef<HTMLElement>(null)
  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) { setOrgOpen(false); setUserOpen(false) }
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [])

  return (
    <header ref={ref} className="h-14 flex-shrink-0 flex items-center gap-3 px-3 border-b border-border bg-surface-1/80 backdrop-blur relative z-30">
      <button onClick={onToggle} aria-label="Toggle menu"
        className="w-9 h-9 rounded-md border border-border hover:border-border-bright text-accent-amber flex items-center justify-center transition-colors">
        <span className="relative w-4 h-4">
          <Menu className={`w-4 h-4 absolute inset-0 transition-all duration-300 ${collapsed ? 'opacity-100 rotate-0' : 'opacity-0 -rotate-90'}`} />
          <X    className={`w-4 h-4 absolute inset-0 transition-all duration-300 ${collapsed ? 'opacity-0 rotate-90' : 'opacity-100 rotate-0'}`} />
        </span>
      </button>

      <img src="/logo-wordmark.svg" alt="harbore" className="h-8 w-auto" />

      <div className="h-6 w-px bg-border mx-1" />

      {/* Organization switcher */}
      <div className="relative">
        <button onClick={() => { setOrgOpen(o => !o); setUserOpen(false) }}
          className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-surface-3 border border-border hover:border-border-bright text-sm text-gray-200 transition-colors">
          <Building2 className="w-3.5 h-3.5 text-accent-amber" />
          <span className="max-w-[160px] truncate">{activeOrg?.name ?? 'No organization'}</span>
          <ChevronDown className={`w-3.5 h-3.5 text-gray-500 transition-transform ${orgOpen ? 'rotate-180' : ''}`} />
        </button>
        {orgOpen && (
          <div className="absolute left-0 mt-1 w-64 card p-1 animate-fade-in">
            <div className="px-2 py-1 text-[10px] uppercase tracking-wider text-gray-500">Organizations</div>
            {orgs.length === 0 && <div className="px-2 py-1.5 text-sm text-gray-500">None yet</div>}
            {orgs.map(o => (
              <button key={o.id} onClick={() => { setActiveOrg(o.id); setOrgOpen(false) }}
                className="w-full flex items-center justify-between px-2 py-1.5 rounded text-sm text-gray-200 hover:bg-white/5">
                <span className="truncate">{o.name}</span>
                {o.id === activeOrg?.id && <Check className="w-3.5 h-3.5 text-accent-amber" />}
              </button>
            ))}
            <div className="border-t border-border my-1" />
            <button onClick={() => { navigate('/settings'); setOrgOpen(false) }}
              className="w-full flex items-center gap-2 px-2 py-1.5 rounded text-sm text-gray-400 hover:bg-white/5">
              <Plus className="w-3.5 h-3.5" /> Manage organizations
            </button>
          </div>
        )}
      </div>

      <div className="flex-1" />

      <div className="relative hidden md:block w-64">
        <Search className="w-3.5 h-3.5 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
        <input placeholder="Search…" className="input pl-9 py-1.5 text-sm" />
      </div>

      <button aria-label="Notifications" className="relative w-9 h-9 rounded-md hover:bg-white/5 text-gray-400 flex items-center justify-center transition-colors">
        <Bell className="w-4 h-4" />
        <span className="absolute top-2 right-2 w-1.5 h-1.5 rounded-full bg-accent-amber" />
      </button>

      <div className="relative">
        <button onClick={() => { setUserOpen(u => !u); setOrgOpen(false) }}
          className="flex items-center gap-2 pl-1 pr-2 py-1 rounded-md hover:bg-white/5 transition-colors">
          <div className="w-7 h-7 rounded-full bg-accent-amber/20 flex items-center justify-center overflow-hidden">
            {user?.avatar
              ? <img src={user.avatar} alt="" className="w-full h-full object-cover" />
              : <span className="text-[11px] font-bold text-accent-amber uppercase">{user?.name?.[0] ?? 'U'}</span>}
          </div>
          <div className="text-left hidden sm:block">
            <div className="text-xs font-medium text-gray-200 leading-none">{user?.name}</div>
            <div className="text-[10px] text-gray-500 capitalize mt-0.5">{user?.role}</div>
          </div>
          <ChevronDown className={`w-3.5 h-3.5 text-gray-500 transition-transform ${userOpen ? 'rotate-180' : ''}`} />
        </button>
        {userOpen && (
          <div className="absolute right-0 mt-1 w-48 card p-1 animate-fade-in">
            <button onClick={() => { navigate('/settings'); setUserOpen(false) }} className="w-full flex items-center gap-2 px-2 py-1.5 rounded text-sm text-gray-200 hover:bg-white/5"><Settings className="w-3.5 h-3.5" /> Settings</button>
            <button onClick={() => { navigate('/about'); setUserOpen(false) }} className="w-full flex items-center gap-2 px-2 py-1.5 rounded text-sm text-gray-200 hover:bg-white/5"><Info className="w-3.5 h-3.5" /> About</button>
            <div className="border-t border-border my-1" />
            <button onClick={logout} className="w-full flex items-center gap-2 px-2 py-1.5 rounded text-sm text-[#FF7A8A] hover:bg-white/5"><LogOut className="w-3.5 h-3.5" /> Log out</button>
          </div>
        )}
      </div>
    </header>
  )
}
