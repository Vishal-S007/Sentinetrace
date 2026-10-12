import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'

import { useAuth } from './AuthContext'

export function RequireAuth({ children }: { children: ReactNode }) {
  const { state } = useAuth()
  const location = useLocation()
  if (state.status === 'loading') {
    return (
      <p role="status" className="p-8 text-ink-dim">
        Loading…
      </p>
    )
  }
  if (state.status === 'anonymous') {
    return <Navigate to="/login" replace state={{ from: location.pathname, reason: state.reason }} />
  }
  return <>{children}</>
}

export function RequirePermission({ permission, children }: { permission: string; children: ReactNode }) {
  const { can } = useAuth()
  if (!can(permission)) {
    return (
      <div role="alert" className="max-w-xl rounded-md border border-line bg-panel p-4 text-sm">
        <p className="font-medium">Access denied</p>
        <p className="mt-1 text-ink-dim">Your role does not include the “{permission}” permission.</p>
      </div>
    )
  }
  return <>{children}</>
}
