import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { getOrgs } from '../api/client'
import type { Organization } from '../types'
import { useAuth } from './useAuth'

interface OrgCtx {
  orgs: Organization[]
  activeOrgId: string | null
  activeOrg: Organization | null
  setActiveOrg: (id: string) => void
  refreshOrgs: () => Promise<void>
  loading: boolean
}

const Ctx = createContext<OrgCtx>({
  orgs: [], activeOrgId: null, activeOrg: null,
  setActiveOrg: () => {}, refreshOrgs: async () => {}, loading: true,
})

export function OrgProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth()
  const [orgs, setOrgs] = useState<Organization[]>([])
  const [activeOrgId, setActiveOrgId] = useState<string | null>(localStorage.getItem('harbore_org'))
  const [loading, setLoading] = useState(true)

  const refreshOrgs = async () => {
    try {
      const list = await getOrgs()
      setOrgs(list)
      const stored = localStorage.getItem('harbore_org')
      const next = list.find(o => o.id === stored)?.id ?? list[0]?.id ?? null
      if (next) {
        localStorage.setItem('harbore_org', next)
        setActiveOrgId(next)
      }
    } catch {
      /* ignore — surfaced on the pages that need org data */
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (user) refreshOrgs()
    else setLoading(false)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user])

  const setActiveOrg = (id: string) => {
    localStorage.setItem('harbore_org', id)
    setActiveOrgId(id)
    // Reload so every org-scoped view re-fetches against the new organization.
    window.location.reload()
  }

  const activeOrg = orgs.find(o => o.id === activeOrgId) ?? null

  return (
    <Ctx.Provider value={{ orgs, activeOrgId, activeOrg, setActiveOrg, refreshOrgs, loading }}>
      {children}
    </Ctx.Provider>
  )
}

export const useOrg = () => useContext(Ctx)
