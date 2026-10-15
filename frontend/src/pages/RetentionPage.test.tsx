import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import { json, makeMe, mockApi, renderWithAuth, setCsrfCookie } from '../test/utils'
import { RetentionPage } from './RetentionPage'

const counts = (over = {}) => ({
  cutoff: '2026-07-15T10:00:00Z',
  older_than_days: 90,
  alerts: 3,
  evidence_links: 40,
  events: 12345,
  ingestion_errors: 2,
  stored_files: 1,
  stored_bytes: 2048,
  min_days: 7,
  auto_days: null,
  ...over,
})

describe('RetentionPage', () => {
  it('previews and purges only after typing PURGE', async () => {
    setCsrfCookie('tok')
    let after = false
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('admin')),
      'GET /api/admin/retention': (c) =>
        json(200, after ? counts({ alerts: 0, evidence_links: 0, events: 0, ingestion_errors: 0, stored_files: 0, stored_bytes: 0, older_than_days: 30 }) : counts({ older_than_days: c.url.includes('=30') ? 30 : 90 })),
      'POST /api/admin/retention/purge': () => {
        after = true
        return json(200, counts({ older_than_days: 30 }))
      },
    })
    renderWithAuth(<RetentionPage />, '/admin/retention')
    expect(await screen.findByRole('row', { name: /Events\s*12,345/ })).toBeInTheDocument()
    expect(screen.getByText('(2.0 KB)')).toBeInTheDocument()

    const days = screen.getByLabelText(/Keep data newer than/)
    await userEvent.clear(days)
    await userEvent.type(days, '30')
    await userEvent.click(screen.getByRole('button', { name: 'Preview' }))
    const purge = await screen.findByRole('button', { name: 'Purge data older than 30 days' })
    expect(purge).toBeDisabled()
    await userEvent.type(screen.getByLabelText('Type PURGE to confirm'), 'purge')
    expect(purge).toBeDisabled()
    await userEvent.clear(screen.getByLabelText('Type PURGE to confirm'))
    await userEvent.type(screen.getByLabelText('Type PURGE to confirm'), 'PURGE')
    await userEvent.click(purge)
    expect(await screen.findByText(/Removed 3 alerts, 12,345 events/)).toBeInTheDocument()
    expect(await screen.findByText('Nothing is eligible with this retention period.')).toBeInTheDocument()
    const post = calls.find((c) => c.method === 'POST')!
    expect(post.body).toEqual({ older_than_days: 30, confirm: 'PURGE' })
    expect(post.headers['X-CSRF-Token']).toBe('tok')
  })

  it('shows the minimum-period error from the server', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('admin')),
      'GET /api/admin/retention': (c) =>
        c.url.includes('=3') ? json(422, { detail: 'Retention must be at least 7 days (ST_RETENTION_MIN_DAYS); got 3' }) : json(200, counts({ auto_days: 180 })),
    })
    renderWithAuth(<RetentionPage />, '/admin/retention')
    expect(await screen.findByText(/Automatic purge is on/)).toHaveTextContent('older than 180 days')
    const days = screen.getByLabelText(/Keep data newer than/)
    await userEvent.clear(days)
    await userEvent.type(days, '3')
    await userEvent.click(screen.getByRole('button', { name: 'Preview' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('at least 7 days')
    expect(screen.queryByRole('region', { name: 'Purge' })).not.toBeInTheDocument()
  })
})
