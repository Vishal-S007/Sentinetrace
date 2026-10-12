import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import type { AuditEntry } from '../api/client'
import { json, makeMe, mockApi, renderWithAuth } from '../test/utils'
import { AuditPage } from './AuditPage'

function entry(id: number, action = 'auth.login.success'): AuditEntry {
  return {
    id,
    occurred_at: '2026-10-12T10:00:00Z',
    actor_user_id: 1,
    actor_username: 'alice',
    action,
    target_type: 'session',
    target_id: String(id),
    ip: '203.0.113.5',
    request_id: 'abc',
    details: id === 3 ? { role: { from: 'viewer', to: 'analyst' } } : {},
  }
}

describe('AuditPage', () => {
  it('renders entries and loads older pages with keyset pagination', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('admin')),
      'GET /api/audit': (call) =>
        call.url.includes('before_id=2')
          ? json(200, { items: [entry(1)], next_before_id: null })
          : json(200, { items: [entry(3), entry(2)], next_before_id: 2 }),
    })
    renderWithAuth(<AuditPage />)
    expect(await screen.findByText('Showing 2 entries')).toBeInTheDocument()
    expect(screen.getByText('{"role":{"from":"viewer","to":"analyst"}}')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Load older entries' }))
    expect(await screen.findByText('Showing 3 entries')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Load older entries' })).not.toBeInTheDocument()
    expect(calls.filter((c) => c.url.startsWith('/api/audit'))).toHaveLength(2)
  })

  it('applies filters as query parameters', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('admin')),
      'GET /api/audit': () => json(200, { items: [], next_before_id: null }),
    })
    renderWithAuth(<AuditPage />)
    expect(await screen.findByText('No audit entries match these filters.')).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText('Action'), 'auth.login.failure')
    await userEvent.type(screen.getByLabelText('Actor'), 'mallory')
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }))
    await screen.findByText('No audit entries match these filters.')
    const last = calls.filter((c) => c.url.startsWith('/api/audit')).at(-1)!
    expect(last.url).toContain('action=auth.login.failure')
    expect(last.url).toContain('actor=mallory')
  })

  it('shows an error state', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('admin')),
      'GET /api/audit': () => json(403, { detail: 'Insufficient permissions' }),
    })
    renderWithAuth(<AuditPage />)
    expect(await screen.findByRole('alert')).toHaveTextContent('Insufficient permissions')
  })
})
