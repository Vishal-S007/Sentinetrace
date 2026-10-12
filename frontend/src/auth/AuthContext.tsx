import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

import { api, ApiError, setUnauthorizedListener, type Me } from '../api/client'

export type AuthState =
  | { status: 'loading' }
  | { status: 'anonymous'; reason?: 'expired' | 'logged_out' }
  | { status: 'authenticated'; me: Me }

interface AuthValue {
  state: AuthState
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  can: (permission: string) => boolean
}

const AuthContext = createContext<AuthValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ status: 'loading' })

  useEffect(() => {
    let active = true
    api
      .me()
      .then((me) => active && setState({ status: 'authenticated', me }))
      .catch(() => active && setState({ status: 'anonymous' }))
    // Any 401 from a later request means the session ended (expired, revoked, logged out elsewhere).
    setUnauthorizedListener(() => setState({ status: 'anonymous', reason: 'expired' }))
    return () => {
      active = false
      setUnauthorizedListener(null)
    }
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const me = await api.login(username, password)
    setState({ status: 'authenticated', me })
  }, [])

  const logout = useCallback(async () => {
    try {
      await api.logout()
    } catch (err) {
      // Already logged out server-side is fine; anything else is surfaced.
      if (!(err instanceof ApiError && err.status === 401)) throw err
    }
    setState({ status: 'anonymous', reason: 'logged_out' })
  }, [])

  const value = useMemo<AuthValue>(
    () => ({
      state,
      login,
      logout,
      can: (permission) => state.status === 'authenticated' && state.me.permissions.includes(permission),
    }),
    [state, login, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
