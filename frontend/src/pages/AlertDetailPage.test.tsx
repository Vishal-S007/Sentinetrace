import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'

import { assignees, makeAlertDetail } from '../test/fixtures'
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

const emptyActivity = { notes: [], history: [], incidents: [] }
const common = {
  'GET /api/alerts/11/activity': () => json(200, emptyActivity),
  'GET /api/assignees': () => json(200, assignees),
  'GET /api/incidents': () => json(200, { items: [], next_before_id: null }),
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
      ...common,
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
      ...common,
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
      ...common,
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
      ...common,
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/alerts/11': () => json(200, makeAlertDetail({ rule_id: 'ST-CORR-001', details: { member_alert_ids: [1, 2], member_rules: ['ST-WEB-001', 'ST-WEB-006'] } })),
      'GET /api/alerts/11/evidence': () => json(200, evidence),
    })
    render()
    expect(await screen.findByRole('link', { name: 'Alert #2' })).toHaveAttribute('href', '/alerts/2')
  })

  it('shows not found', async () => {
    mockApi({
      ...common,
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/alerts/11': () => json(404, { detail: 'Alert not found' }),
    })
    render()
    expect(await screen.findByRole('alert')).toHaveTextContent('Alert not found')
  })
})

describe('AlertDetailPage investigation', () => {
  it('assigns an owner and shows the change in history', async () => {
    setCsrfCookie('tok')
    let activity: unknown = emptyActivity
    const { calls } = mockApi({
      ...common,
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/alerts/11': () => json(200, makeAlertDetail()),
      'GET /api/alerts/11/evidence': () => json(200, evidence),
      'GET /api/alerts/11/activity': () => json(200, activity),
      'PATCH /api/alerts/11': () => {
        activity = {
          ...emptyActivity,
          history: [{ id: 1, occurred_at: '2026-10-13T10:00:00Z', actor: 'analystuser', action: 'alert.assign', details: { from: null, to: 'ana', note: '' } }],
        }
        return json(200, makeAlertDetail({ assigned_to: 2, assignee: 'ana' }))
      },
    })
    render()
    const owner = await screen.findByLabelText('Alert owner')
    await screen.findByRole('option', { name: 'ana (analyst)' })
    await userEvent.selectOptions(owner, '2')
    expect(await screen.findByText('Assigned to ana.')).toBeInTheDocument()
    const patch = calls.find((c) => c.method === 'PATCH')!
    expect(patch.body).toEqual({ assigned_to: 2 })
    expect(patch.headers['X-CSRF-Token']).toBe('tok')
    const history = screen.getByRole('region', { name: 'History' })
    expect(await within(history).findByText('Owner changed')).toBeInTheDocument()
    expect(within(history).getByText('unassigned → ana')).toBeInTheDocument()
  })

  it('adds a note and shows it as plain text', async () => {
    let notes: unknown[] = []
    const { calls } = mockApi({
      ...common,
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/alerts/11': () => json(200, makeAlertDetail()),
      'GET /api/alerts/11/evidence': () => json(200, evidence),
      'GET /api/alerts/11/activity': () => json(200, { ...emptyActivity, notes }),
      'POST /api/alerts/11/notes': (c) => {
        const b = c.body as { kind: string; body: string; event_id: number | null }
        notes = [{ id: 1, kind: b.kind, body: b.body, event_id: b.event_id, author: 'analystuser', created_at: '2026-10-13T10:00:00Z' }]
        return json(201, notes[0])
      },
    })
    render()
    const section = await screen.findByRole('region', { name: 'Investigation notes' })
    await userEvent.selectOptions(within(section).getByLabelText('Entry type'), 'evidence')
    await userEvent.type(within(section).getByLabelText('Event ID (optional)'), '501')
    await userEvent.type(within(section).getByLabelText('Note text'), '<script>x</script> matches WAF block')
    await userEvent.click(within(section).getByRole('button', { name: 'Add to record' }))
    expect(await within(section).findByText('<script>x</script> matches WAF block')).toBeInTheDocument()
    expect(within(section).getByRole('listitem')).toHaveTextContent('Evidence reference')
    expect(within(section).getByRole('listitem')).toHaveTextContent('References event #501')
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ kind: 'evidence', body: '<script>x</script> matches WAF block', event_id: 501 })
    expect(document.querySelector('script')).toBeNull()
  })

  it('creates a new incident from the alert', async () => {
    const { calls } = mockApi({
      ...common,
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/alerts/11': () => json(200, makeAlertDetail()),
      'GET /api/alerts/11/evidence': () => json(200, evidence),
      'POST /api/incidents': () => json(201, { id: 9 }),
    })
    renderWithAuth(
      <Routes>
        <Route path="/alerts/:id" element={<AlertDetailPage />} />
        <Route path="/incidents/:id" element={<p>incident page</p>} />
      </Routes>,
      '/alerts/11',
    )
    const section = await screen.findByRole('region', { name: 'Incidents' })
    expect(within(section).getByText('Not part of an incident.')).toBeInTheDocument()
    const picker = within(section).getByLabelText('Add to incident')
    await waitFor(() => expect(picker).toBeEnabled())
    await userEvent.selectOptions(picker, 'new')
    await userEvent.click(within(section).getByRole('button', { name: 'Add' }))
    expect(await screen.findByText('incident page')).toBeInTheDocument()
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({
      title: 'SQL injection indicators from 203.0.113.10',
      alert_ids: [11],
    })
  })

  it('lists incidents the alert belongs to, read-only for viewers', async () => {
    mockApi({
      ...common,
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/alerts/11': () => json(200, makeAlertDetail()),
      'GET /api/alerts/11/evidence': () => json(200, evidence),
      'GET /api/alerts/11/activity': () =>
        json(200, { ...emptyActivity, incidents: [{ id: 4, title: 'Campaign', status: 'contained', severity: 'high' }] }),
    })
    render()
    const section = await screen.findByRole('region', { name: 'Incidents' })
    expect(within(section).getByRole('link', { name: '#4 Campaign' })).toHaveAttribute('href', '/incidents/4')
    expect(within(section).getByText('Contained')).toBeInTheDocument()
    expect(within(section).queryByLabelText('Add to incident')).not.toBeInTheDocument()
    expect(screen.queryByRole('form', { name: 'Add note' })).not.toBeInTheDocument()
  })
})
