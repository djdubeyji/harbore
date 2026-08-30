import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { getMe, logout as apiLogout } from '../api/client'
import type { User } from '../types'

interface AuthCtx {
  user: User | null
  loading: boolean
  logout: () => void
  refresh: () => Promise<void>
}

const Ctx = createContext<AuthCtx>({ user: null, loading: true, logout: () => {}, refresh: async () => {} })

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  const refresh = async () => {
    const token = localStorage.getItem('harbore_token')
    if (!token) { setLoading(false); return }
    try {
      const u = await getMe()
      setUser(u)
    } catch {
      localStorage.removeItem('harbore_token')
      setUser(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { refresh() }, [])

  const logout = () => { setUser(null); apiLogout() }

  return <Ctx.Provider value={{ user, loading, logout, refresh }}>{children}</Ctx.Provider>
}

export const useAuth = () => useContext(Ctx)
