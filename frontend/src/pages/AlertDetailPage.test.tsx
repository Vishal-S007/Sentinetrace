import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'

import { makeAlertDetail } from '../test/fixtures'
import { json, makeMe, mockApi, renderWithAuth, setCsrfCookie } from '../test/utils'
import { AlertDetailPage } from './AlertDetailPage'

const evidence = {
  items: [{
    event_id: 501, indicator: 'union_select', event_time: '2026-10-01T01:14:10Z', event_type: 'http_request',
    source_ip: '203.0.113.10', username: null, http_method: 'GET', path: '/products', query: 'id=1',
    http_status: 500, user_agent: 'sqlmap', source_id: 1, file_id: 1, line_number: 1081,
    raw_line: '<img src=x onerror=alert(1)> GET /products?id=1 union select',
  }],
  next_after_id: null, total_linked: 1, total_events: 6, truncated: false,
}

function render() {
  return renderWithAuth(
    <Routes>
      <Route path="/alerts/:id" element={<AlertDetailPage />} />
    </Routes>,
    '/alerts/11',
  )
}

describe('AlertDetailPage', () => {
  it('explains the alert and shows evidence as plain text', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/alerts/11': () => json(200, makeAlertDetail()),
      'GET /api/alerts/11/evidence': () => json(200, evidence),
    })
    render()
    expect(await screen.findByRole('heading', { name: 'SQL injection indicators from 203.0.113.10' })).toBeInTheDocument()
    expect(screen.getByText(/Indicator only/)).toBeInTheDocument()
    expect(screen.getByText('The User-Agent identifies a known attack tool.')).toBeInTheDocument()
    expect(screen.getAllByRole('listitem').some((li) => li.textContent === 'Check database logs.')).toBe(true)
    // Untrusted log content is displayed literally, never as HTML.
    expect(await screen.findByText(/<img src=x onerror=alert\(1\)>/)).toBeInTheDocument()
    expect(document.querySelector('main img, section img')).toBeNull()
    expect(screen.getByRole('link', { name: 'Open in event explorer →' })).toHaveAttribute('href', '/events?alert_id=11')
    expect(screen.getByRole('link', { name: '203.0.113.10' })).toHaveAttribute('href', '/events?source_ip=203.0.113.10')
    // Viewers cannot triage.
    expect(screen.queryByRole('region', { name: 'Triage' })).not.toBeInTheDocument()
  })

  it('lets analysts change status with a note (CSRF header sent)', async () => {
    setCsrfCookie('tok')
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/alerts/11': () => json(200, makeAlertDetail()),
      'GET /api/alerts/11/evidence': () => json(200, evidence),
      'PATCH /api/alerts/11': (c) => json(200, makeAlertDetail({ status: (c.body as { status: 'resolved' }).status })),
    })
    render()
    await userEvent.type(await screen.findByLabelText(/Note for the audit trail/), 'benign scanner')
    await userEvent.click(screen.getByRole('button', { name: 'Mark false positive' }))
    expect(await screen.findByText('Status changed to False positive.')).toBeInTheDocument()
    const patch = calls.find((c) => c.method === 'PATCH')!
    expect(patch.body).toEqual({ status: 'false_positive', note: 'benign scanner' })
    expect(patch.headers['X-CSRF-Token']).toBe('tok')
    expect(screen.queryByRole('button', { name: 'Mark false positive' })).not.toBeInTheDocument()
  })

  it('shows a triage error', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/alerts/11': () => json(200, makeAlertDetail()),
      'GET /api/alerts/11/evidence': () => json(200, evidence),
      'PATCH /api/alerts/11': () => json(403, { detail: 'Insufficient permissions' }),
    })
    render()
    await userEvent.click(await screen.findByRole('button', { name: 'Mark resolved' }))
    expect(await screen.findByText('Insufficient permissions')).toBeInTheDocument()
  })

  it('links correlated member alerts', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/alerts/11': () => json(200, makeAlertDetail({ rule_id: 'ST-CORR-001', details: { member_alert_ids: [1, 2], member_rules: ['ST-WEB-001', 'ST-WEB-006'] } })),
      'GET /api/alerts/11/evidence': () => json(200, evidence),
    })
    render()
    expect(await screen.findByRole('link', { name: 'Alert #2' })).toHaveAttribute('href', '/alerts/2')
  })

  it('shows not found', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/alerts/11': () => json(404, { detail: 'Alert not found' }),
    })
    render()
    expect(await screen.findByRole('alert')).toHaveTextContent('Alert not found')
  })
})
