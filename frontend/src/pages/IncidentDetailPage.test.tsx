import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'

import { assignees, makeAlert, makeIncident } from '../test/fixtures'
import { json, makeMe, mockApi, renderWithAuth, setCsrfCookie } from '../test/utils'
import { IncidentDetailPage } from './IncidentDetailPage'

function render() {
  return renderWithAuth(
    <Routes>
      <Route path="/incidents/:id" element={<IncidentDetailPage />} />
    </Routes>,
    '/incidents/5',
  )
}

describe('IncidentDetailPage', () => {
  it('shows summary, alerts, timeline and report links', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/incidents/5': () => json(200, makeIncident()),
      'GET /api/assignees': () => json(200, assignees),
    })
    render()
    expect(await screen.findByRole('heading', { name: 'SQL injection campaign from 203.0.113.10' })).toBeInTheDocument()
    expect(screen.getByText('Scanner followed by injection attempts.')).toBeInTheDocument()
    const alerts = screen.getByRole('region', { name: 'Linked alerts' })
    expect(within(alerts).getByRole('link', { name: 'SQL injection indicators from 203.0.113.10' })).toHaveAttribute('href', '/alerts/11')

    const timeline = screen.getByRole('region', { name: 'Timeline' })
    const items = within(timeline).getAllByRole('listitem')
    expect(items.map((li) => li.querySelector('p:nth-of-type(2)')?.textContent)).toEqual([
      'First observed: SQL injection indicators from 203.0.113.10',
      'Incident created',
      'Action taken',
    ])
    // Note text is shown literally.
    expect(within(timeline).getByText('Blocked <b>IP</b> at WAF')).toBeInTheDocument()
    expect(within(timeline).getByText('References event #501')).toBeInTheDocument()

    const report = screen.getByRole('region', { name: 'Report' })
    expect(within(report).getByRole('link', { name: 'Download Markdown' })).toHaveAttribute('href', '/api/incidents/5/report?format=markdown')
    expect(within(report).getByRole('link', { name: 'JSON' })).toHaveAttribute('href', '/api/incidents/5/report?format=json')
  })

  it('saves only changed fields with the CSRF header', async () => {
    setCsrfCookie('tok')
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/incidents/5': () => json(200, makeIncident()),
      'GET /api/assignees': () => json(200, assignees),
      'PATCH /api/incidents/5': () => json(200, makeIncident({ status: 'contained', assigned_to: 3, assignee: 'root' })),
    })
    render()
    const panel = await screen.findByRole('form', { name: 'Manage incident' })
    const save = within(panel).getByRole('button', { name: 'Save changes' })
    expect(save).toBeDisabled()
    await userEvent.selectOptions(within(panel).getByLabelText('Status'), 'contained')
    await screen.findByRole('option', { name: 'root (admin)' })
    await userEvent.selectOptions(within(panel).getByLabelText('Incident owner'), '3')
    await userEvent.type(within(panel).getByLabelText(/Reason/), 'blocked upstream')
    await userEvent.click(save)
    await waitFor(() => expect(screen.getByText('Owner: root')).toBeInTheDocument())
    const patch = calls.find((c) => c.method === 'PATCH')!
    expect(patch.body).toEqual({ status: 'contained', assigned_to: 3, note: 'blocked upstream' })
    expect(patch.headers['X-CSRF-Token']).toBe('tok')
  })

  it('links and removes alerts', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/incidents/5': () => json(200, makeIncident()),
      'GET /api/assignees': () => json(200, assignees),
      'POST /api/incidents/5/alerts': () =>
        json(200, makeIncident({ alert_count: 2, alerts: [makeAlert(), makeAlert({ id: 12, title: 'Burst from 203.0.113.10' })] })),
      'DELETE /api/incidents/5/alerts/11': () => json(200, makeIncident({ alert_count: 1, alerts: [makeAlert({ id: 12, title: 'Burst from 203.0.113.10' })] })),
    })
    render()
    await userEvent.type(await screen.findByLabelText('Alert IDs to link'), '12, 12 x')
    await userEvent.click(screen.getByRole('button', { name: 'Link alerts' }))
    expect(await screen.findByText('Burst from 203.0.113.10')).toBeInTheDocument()
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ alert_ids: [12] })
    await userEvent.click(screen.getByRole('button', { name: 'Remove alert 11' }))
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Remove alert 11' })).not.toBeInTheDocument())
  })

  it('records an action note and reloads the timeline', async () => {
    let incident = makeIncident({ timeline: [] })
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/incidents/5': () => json(200, incident),
      'GET /api/assignees': () => json(200, assignees),
      'POST /api/incidents/5/notes': () => {
        incident = makeIncident()
        return json(201, {})
      },
    })
    render()
    expect(await screen.findByText('Nothing recorded yet.')).toBeInTheDocument()
    await userEvent.selectOptions(screen.getByLabelText('Entry type'), 'action')
    await userEvent.type(screen.getByLabelText('Note text'), 'Blocked IP at WAF')
    await userEvent.click(screen.getByRole('button', { name: 'Add to record' }))
    expect(await screen.findByText('Incident created')).toBeInTheDocument()
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ kind: 'action', body: 'Blocked IP at WAF', event_id: null })
  })

  it('is read-only for viewers and has no export', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/incidents/5': () => json(200, makeIncident()),
    })
    render()
    await screen.findByRole('region', { name: 'Timeline' })
    expect(screen.queryByRole('form', { name: 'Manage incident' })).not.toBeInTheDocument()
    expect(screen.queryByRole('form', { name: 'Add note' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Remove alert/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('region', { name: 'Report' })).not.toBeInTheDocument()
  })

  it('shows not found', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/incidents/5': () => json(404, { detail: 'Incident not found' }),
    })
    render()
    expect(await screen.findByRole('alert')).toHaveTextContent('Incident not found')
  })
})
