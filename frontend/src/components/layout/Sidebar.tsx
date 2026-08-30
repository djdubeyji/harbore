import { NavLink } from 'react-router-dom'
import { Shield, Activity, FolderOpen, Settings, ChevronRight, Terminal, Info, Network, Lock, CreditCard, ClipboardCheck } from 'lucide-react'

const nav = [
  { to: '/',           icon: Activity,        label: 'Dashboard' },
  { to: '/scans',      icon: Shield,          label: 'Scans' },
  { to: '/assets',     icon: Network,         label: 'Asset Discovery' },
  { to: '/tls',        icon: Lock,            label: 'TLS Certificates' },
  { to: '/pci',        icon: CreditCard,      label: 'PCI DSS 4.0.1' },
  { to: '/compliance', icon: ClipboardCheck,  label: 'Compliance' },
  { to: '/console',    icon: Terminal,        label: 'Console' },
  { to: '/projects',   icon: FolderOpen,      label: 'Projects' },
  { to: '/settings',   icon: Settings,        label: 'Settings' },
  { to: '/about',      icon: Info,            label: 'About' },
]

export function Sidebar({ collapsed }: { collapsed: boolean }) {
  return (
    <aside
      className={`flex-shrink-0 bg-surface-1 border-r border-border overflow-hidden
                  transition-[width,opacity] duration-300 ease-in-out
                  ${collapsed ? 'w-0 opacity-0 border-r-0' : 'w-56 opacity-100'}`}
    >
      <div className="w-56 h-full flex flex-col">
        <nav className="flex-1 py-4 px-2 space-y-0.5 overflow-y-auto">
          {nav.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-2.5 px-3 py-2 rounded-md text-sm transition-colors ${
                  isActive
                    ? 'bg-accent-blue/15 text-accent-blue'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <Icon className="w-4 h-4 flex-shrink-0" />
                  <span className="flex-1">{label}</span>
                  {isActive && <ChevronRight className="w-3 h-3 opacity-50" />}
                </>
              )}
            </NavLink>
          ))}
        </nav>
      </div>
    </aside>
  )
}
