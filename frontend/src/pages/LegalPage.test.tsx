import { screen, within } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'

import type { LegalFacts } from '../api/client'
import { json, mockApi, renderWithAuth } from '../test/utils'
import { LegalPage } from './LegalPage'

function facts(operator: Partial<LegalFacts['operator']> = {}): LegalFacts {
  return {
    operator: { name: 'Example Security Team', contact: 'privacy@example.com', address: '1 Example Road', ...operator },
    effective_date: '2026-10-19',
    retention: {
      login_attempt_days: 30,
      session_retention_days: 7,
      session_idle_minutes: 60,
      session_absolute_hours: 12,
      data_retention_days: null,
      data_retention_min_days: 7,
    },
    cookies: [
      { name: 'st_session', purpose: 'Keeps you signed in.', duration_hours: 12, http_only: true, same_site: 'Lax' },
      { name: 'st_csrf', purpose: 'Blocks forged requests.', duration_hours: 12, http_only: false, same_site: 'Strict' },
    ],
  }
}

function show(path: string, body: LegalFacts = facts()) {
  mockApi({
    'GET /api/auth/me': () => json(401, { detail: 'Not authenticated' }),
    'GET /api/legal': () => json(200, body),
  })
  renderWithAuth(
    <Routes>
      <Route path="/legal/:slug" element={<LegalPage />} />
    </Routes>,
    path,
  )
}

describe('LegalPage', () => {
  it('shows the privacy policy with operator details and retention periods', async () => {
    show('/legal/privacy')
    expect(await screen.findByRole('heading', { level: 1, name: 'Privacy policy' })).toBeInTheDocument()
    expect(await screen.findAllByText('Example Security Team')).not.toHaveLength(0)
    expect(screen.getByRole('link', { name: 'privacy@example.com' })).toHaveAttribute('href', 'mailto:privacy@example.com')
    const retention = screen.getByRole('region', { name: 'Retention periods' })
    expect(within(retention).getByText(/30 days, then deleted automatically/)).toBeInTheDocument()
    expect(screen.getByText('Effective 2026-10-19')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Back to sign in' })).toHaveAttribute('href', '/login')
  })

  it('warns when the operator has not published their details', async () => {
    show('/legal/terms', facts({ name: '', contact: '', address: '' }))
    expect(await screen.findByRole('note')).toHaveTextContent('has not published their details')
    expect(screen.getByRole('heading', { level: 2, name: '4. Fees and refunds' })).toBeInTheDocument()
  })

  it('lists exactly the cookies the server reports', async () => {
    show('/legal/cookies')
    const table = await screen.findByRole('region', { name: 'Cookies used' })
    expect(within(table).getByText('st_session')).toBeInTheDocument()
    expect(within(table).getByText('st_csrf')).toBeInTheDocument()
    expect(within(table).getAllByRole('row')).toHaveLength(3)
  })

  it('shows not found for an unknown document', async () => {
    show('/legal/nothing')
    expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument()
  })
})
