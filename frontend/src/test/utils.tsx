import { render } from '@testing-library/react'
import type { ReactElement } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'

import type { Me } from '../api/client'
import { AuthProvider } from '../auth/AuthContext'

export function json(status: number, body?: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

export interface Call {
  method: string
  url: string
  headers: Record<string, string>
  body: unknown
}

type Handler = (call: Call) => Response | Promise<Response>

/** Route fetch calls by "METHOD /path" (query string ignored for matching). */
export function mockApi(routes: Record<string, Handler>) {
  const calls: Call[] = []
  const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const method = (init?.method ?? 'GET').toUpperCase()
    const call: Call = {
      method,
      url,
      headers: (init?.headers as Record<string, string>) ?? {},
      body: typeof init?.body === 'string' ? JSON.parse(init.body) : init?.body,
    }
    calls.push(call)
    const key = `${method} ${url.split('?')[0]}`
    const handler = routes[key]
    if (!handler) throw new Error(`Unmocked request: ${key}`)
    return handler(call)
  })
  return { spy, calls }
}

export const permissionsByRole = {
  viewer: ['alerts:read', 'events:read', 'incidents:read', 'reports:read', 'rules:read'],
  analyst: [
    'alerts:read', 'alerts:triage', 'events:read', 'incidents:manage', 'incidents:read',
    'logs:import', 'reports:export', 'reports:read', 'rules:read',
  ],
  admin: [
    'alerts:read', 'alerts:triage', 'audit:read', 'events:read', 'incidents:manage', 'incidents:read',
    'logs:import', 'reports:export', 'reports:read', 'rules:manage', 'rules:read', 'settings:manage',
    'users:manage',
  ],
}

export function makeMe(role: keyof typeof permissionsByRole = 'admin', id = 1): Me {
  return {
    user: {
      id,
      username: `${role}user`,
      email: null,
      role,
      is_active: true,
      created_at: '2026-10-01T10:00:00Z',
      last_login_at: '2026-10-12T09:00:00Z',
    },
    permissions: permissionsByRole[role],
  }
}

export function renderWithAuth(ui: ReactElement, path = '/') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>{ui}</AuthProvider>
    </MemoryRouter>,
  )
}

export function setCsrfCookie(value = 'csrf-test-token') {
  document.cookie = `st_csrf=${value}; path=/`
  return value
}
