import { NavLink, Navigate, Route, Routes } from 'react-router-dom'

import { StatusPage } from './pages/StatusPage'

// Only screens that are actually implemented appear here. Each phase adds its own.
const NAV = [{ to: '/status', label: 'System status' }]

export default function App() {
  return (
    <div className="flex h-full">
      <aside className="hidden w-56 shrink-0 flex-col border-r border-line bg-panel md:flex">
        <div className="flex items-center gap-2 px-4 py-4">
          <span aria-hidden className="h-2 w-2 rounded-full bg-accent" />
          <span className="font-semibold tracking-tight">SentinelTrace</span>
        </div>
        <nav aria-label="Main" className="flex flex-col gap-0.5 px-2">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `rounded-md px-3 py-2 text-sm ${isActive ? 'bg-panel-2 text-ink' : 'text-ink-dim hover:text-ink'}`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <main className="flex-1 overflow-y-auto p-4 md:p-8">
        <Routes>
          <Route path="/" element={<Navigate to="/status" replace />} />
          <Route path="/status" element={<StatusPage />} />
          <Route path="*" element={<p className="text-ink-dim">Page not found.</p>} />
        </Routes>
      </main>
    </div>
  )
}
