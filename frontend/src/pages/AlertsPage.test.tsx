import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes, useLocation } from 'react-router-dom'
import { describe, expect, it } from 'vitest'

import { makeAlert } from '../test/fixtures'
import { json, makeMe, mockApi, renderWithAuth } from '../test/utils'
import { AlertsPage } from './AlertsPage'

const rules = [{ rule_id: 'ST-WEB-001', name: 'SQL injection indicators', category: 'web', severity: 'high', enabled: true }]

function render(path = '/alerts') {
  return renderWithAuth(
    <Routes>
      <Route path="/alerts" element={<AlertsPage />} />
    </Routes>,
    path,
  )
}

describe('AlertsPage', () => {
  it('passes URL filters to the API and lists alerts', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/alerts': () => json(200, { items: [makeAlert()], next_before_id: null }),
      'GET /api/rules': () => json(200, rules),
    })
    render('/alerts?severity=high&source_ip=203.0.113.10')
    expect(await screen.findByRole('link', { name: 'SQL injection indicators from 203.0.113.10' })).toHaveAttribute('href', '/alerts/11')
    expect(screen.getByText('high confidence')).toBeInTheDocument()
    const call = calls.find((c) => c.url.startsWith('/api/alerts'))!
    expect(call.url).toContain('severity=high')
    expect(call.url).toContain('source_ip=203.0.113.10')
    expect(screen.getByLabelText('Severity')).toHaveValue('high')
  })

  it('loads older alerts with keyset pagination', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/alerts': (c) =>
        c.url.includes('before_id=11')
          ? json(200, { items: [makeAlert({ id: 5, title: 'Older alert' })], next_before_id: null })
          : json(200, { items: [makeAlert()], next_before_id: 11 }),
      'GET /api/rules': () => json(200, rules),
    })
    render()
    await userEvent.click(await screen.findByRole('button', { name: 'Load older alerts' }))
    expect(await screen.findByText('Older alert')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Load older alerts' })).not.toBeInTheDocument()
    expect(calls.filter((c) => c.url.startsWith('/api/alerts'))).toHaveLength(2)
  })

  it('shows empty and error states', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/alerts': () => json(200, { items: [], next_before_id: null }),
      'GET /api/rules': () => json(500, {}),
    })
    render()
    expect(await screen.findByText(/No alerts match these filters/)).toBeInTheDocument()
  })

  it('reports API errors', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/alerts': () => json(422, { detail: 'source_ip must be a valid IP address' }),
      'GET /api/rules': () => json(200, rules),
    })
    render('/alerts?source_ip=bad')
    expect(await screen.findByRole('alert')).toHaveTextContent('source_ip must be a valid IP address')
  })
})

describe('AlertsPage incidents and exports', () => {
  it('groups selected alerts into a new incident', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/alerts': () => json(200, { items: [makeAlert(), makeAlert({ id: 12, title: 'Burst' })], next_before_id: null }),
      'GET /api/rules': () => json(200, rules),
    })
    renderWithAuth(
      <Routes>
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/incidents/new" element={<NewProbe />} />
      </Routes>,
      '/alerts',
    )
    await userEvent.click(await screen.findByLabelText('Select alert 12'))
    await userEvent.click(screen.getByLabelText('Select alert 11'))
    expect(screen.getByRole('region', { name: 'Selection' })).toHaveTextContent('2 alerts selected')
    await userEvent.click(screen.getByRole('button', { name: 'Create incident' }))
    expect(await screen.findByText('new incident: ?alerts=12,11')).toBeInTheDocument()
  })

  it('offers exports that carry the current filters', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/alerts': () => json(200, { items: [makeAlert({ assignee: 'ana', assigned_to: 2 })], next_before_id: null }),
      'GET /api/rules': () => json(200, rules),
    })
    render('/alerts?severity=high&assigned_to=me')
    expect(await screen.findByRole('link', { name: 'CSV' })).toHaveAttribute('href', '/api/alerts/export?severity=high&assigned_to=me&format=csv')
    expect(screen.getByRole('link', { name: 'JSON' })).toHaveAttribute('href', '/api/alerts/export?severity=high&assigned_to=me&format=json')
    expect(screen.getByText('ana')).toBeInTheDocument()
    expect(screen.getByLabelText('Owner')).toHaveValue('me')
  })

  it('viewers get neither selection nor export', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/alerts': () => json(200, { items: [makeAlert()], next_before_id: null }),
      'GET /api/rules': () => json(200, rules),
    })
    render()
    await screen.findByRole('link', { name: 'SQL injection indicators from 203.0.113.10' })
    expect(screen.queryByLabelText('Select alert 11')).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'CSV' })).not.toBeInTheDocument()
  })
})

function NewProbe() {
  const location = useLocation()
  return <p>new incident: {location.search}</p>
}
