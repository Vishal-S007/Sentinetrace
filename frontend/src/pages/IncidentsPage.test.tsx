import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes, useLocation } from 'react-router-dom'
import { describe, expect, it } from 'vitest'

import { assignees, makeAlert, makeIncident } from '../test/fixtures'
import { json, makeMe, mockApi, renderWithAuth } from '../test/utils'
import { IncidentNewPage } from './IncidentNewPage'
import { IncidentsPage } from './IncidentsPage'

function Keyed() {
  const location = useLocation()
  return <IncidentsPage key={location.search} />
}

describe('IncidentsPage', () => {
  it('lists incidents and applies filters through the URL', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/incidents': () => json(200, { items: [makeIncident({ assignee: 'ana' })], next_before_id: null }),
    })
    renderWithAuth(
      <Routes>
        <Route path="/incidents" element={<Keyed />} />
      </Routes>,
      '/incidents',
    )
    expect(await screen.findByRole('link', { name: 'SQL injection campaign from 203.0.113.10' })).toHaveAttribute('href', '/incidents/5')
    expect(screen.getByText('ana')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'New incident' })).toHaveAttribute('href', '/incidents/new')
    await userEvent.selectOptions(screen.getByLabelText('Owner'), 'me')
    await userEvent.click(screen.getByLabelText('Hide resolved and closed'))
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }))
    await screen.findByRole('link', { name: 'SQL injection campaign from 203.0.113.10' })
    const last = calls.filter((c) => c.url.startsWith('/api/incidents')).at(-1)!
    expect(last.url).toContain('assigned_to=me')
    expect(last.url).toContain('open_only=true')
  })

  it('hides creation for viewers and shows the empty state', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/incidents': () => json(200, { items: [], next_before_id: null }),
    })
    renderWithAuth(<IncidentsPage />, '/incidents')
    expect(await screen.findByText(/No incidents match/)).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'New incident' })).not.toBeInTheDocument()
  })
})

describe('IncidentNewPage', () => {
  it('creates an incident from selected alerts', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/assignees': () => json(200, assignees),
      'GET /api/alerts/11': () => json(200, makeAlert()),
      'GET /api/alerts/12': () => json(200, makeAlert({ id: 12, title: 'Burst', severity: 'medium' })),
      'POST /api/incidents': () => json(201, { id: 9 }),
    })
    renderWithAuth(
      <Routes>
        <Route path="/incidents/new" element={<IncidentNewPage />} />
        <Route path="/incidents/:id" element={<p>created</p>} />
      </Routes>,
      '/incidents/new?alerts=11,12,11,bad',
    )
    const title = await screen.findByLabelText('Title')
    await screen.findByText('#12 Burst')
    expect(title).toHaveValue('SQL injection indicators from 203.0.113.10 and related activity')
    expect(screen.getByText('Linked alerts (2)')).toBeInTheDocument()
    await userEvent.clear(title)
    await userEvent.type(title, 'Web attack')
    await userEvent.click(screen.getByRole('button', { name: 'Create incident' }))
    expect(await screen.findByText('created')).toBeInTheDocument()
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({
      title: 'Web attack',
      summary: '',
      severity: null,
      assigned_to: null,
      alert_ids: [11, 12],
    })
  })

  it('shows server validation errors', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/assignees': () => json(200, assignees),
      'POST /api/incidents': () => json(422, { detail: 'Unknown alert id(s): 99' }),
    })
    renderWithAuth(<IncidentNewPage />, '/incidents/new')
    await userEvent.type(await screen.findByLabelText('Title'), 'x')
    await userEvent.click(screen.getByRole('button', { name: 'Create incident' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Unknown alert id(s): 99')
  })
})
