import { useState } from 'react'
import { NavLink, Navigate, Route, Routes, useNavigate } from 'react-router-dom'

import { ApiError } from './api/client'
import { useAuth } from './auth/AuthContext'
import { RequireAuth, RequirePermission } from './auth/guards'
import { AccountPage } from './pages/AccountPage'
import { AuditPage } from './pages/AuditPage'
import { JobDetailPage } from './pages/JobDetailPage'
import { JobsPage } from './pages/JobsPage'
import { LoginPage } from './pages/LoginPage'
import { SourcesPage } from './pages/SourcesPage'
import { StatusPage } from './pages/StatusPage'
import { UsersPage } from './pages/UsersPage'

// Only screens that are implemented appear here; each later phase adds its own.
const NAV: { to: string; label: string; permission?: string }[] = [
  { to: '/sources', label: 'Log sources', permission: 'events:read' },
  { to: '/jobs', label: 'Ingestion jobs', permission: 'events:read' },
  { to: '/status', label: 'System status' },
  { to: '/admin/users', label: 'Users & roles', permission: 'users:manage' },
  { to: '/admin/audit', label: 'Audit log', permission: 'audit:read' },
]

function Shell() {
  const { state, can, logout } = useAuth()
  const navigate = useNavigate()
  const [logoutError, setLogoutError] = useState<string | null>(null)
  if (state.status !== 'authenticated') return null
  const { user } = state.me

  async function onLogout() {
    setLogoutError(null)
    try {
      await logout()
      navigate('/login', { replace: true })
    } catch (err) {
      setLogoutError(err instanceof ApiError ? err.message : 'Logout failed')
    }
  }

  return (
    <div className="flex h-full flex-col md:flex-row">
      <aside className="flex shrink-0 flex-col border-b border-line bg-panel md:w-56 md:border-b-0 md:border-r">
        <div className="flex items-center gap-2 px-4 py-4">
          <span aria-hidden className="h-2 w-2 rounded-full bg-accent" />
          <span className="font-semibold tracking-tight">SentinelTrace</span>
        </div>
        <nav aria-label="Main" className="flex flex-row gap-0.5 overflow-x-auto px-2 md:flex-col">
          {NAV.filter((item) => !item.permission || can(item.permission)).map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `whitespace-nowrap rounded-md px-3 py-2 text-sm ${isActive ? 'bg-panel-2 text-ink' : 'text-ink-dim hover:text-ink'}`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto hidden border-t border-line p-3 text-sm md:block">
          <NavLink to="/account" className="block truncate font-medium hover:text-accent">
            {user.username}
          </NavLink>
          <p className="text-xs capitalize text-ink-dim">{user.role}</p>
          <button type="button" onClick={() => void onLogout()} className="mt-2 text-xs text-ink-dim hover:text-crit">
            Sign out
          </button>
          {logoutError && (
            <p role="alert" className="mt-1 text-xs text-crit">
              {logoutError}
            </p>
          )}
        </div>
        <div className="flex items-center justify-between border-t border-line px-4 py-2 text-xs md:hidden">
          <NavLink to="/account">{user.username}</NavLink>
          <button type="button" onClick={() => void onLogout()} className="text-ink-dim">
            Sign out
          </button>
        </div>
      </aside>
      <main className="flex-1 overflow-y-auto p-4 md:p-8">
        <Routes>
          <Route path="/" element={<Navigate to={can('events:read') ? '/sources' : '/status'} replace />} />
          <Route
            path="/sources"
            element={
              <RequirePermission permission="events:read">
                <SourcesPage />
              </RequirePermission>
            }
          />
          <Route
            path="/jobs"
            element={
              <RequirePermission permission="events:read">
                <JobsPage />
              </RequirePermission>
            }
          />
          <Route
            path="/jobs/:id"
            element={
              <RequirePermission permission="events:read">
                <JobDetailPage />
              </RequirePermission>
            }
          />
          <Route path="/status" element={<StatusPage />} />
          <Route path="/account" element={<AccountPage />} />
          <Route
            path="/admin/users"
            element={
              <RequirePermission permission="users:manage">
                <UsersPage />
              </RequirePermission>
            }
          />
          <Route
            path="/admin/audit"
            element={
              <RequirePermission permission="audit:read">
                <AuditPage />
              </RequirePermission>
            }
          />
          <Route path="*" element={<p className="text-ink-dim">Page not found.</p>} />
        </Routes>
      </main>
    </div>
  )
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/*"
        element={
          <RequireAuth>
            <Shell />
          </RequireAuth>
        }
      />
    </Routes>
  )
}
