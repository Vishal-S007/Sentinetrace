import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes, useLocation } from 'react-router-dom'
import { describe, expect, it } from 'vitest'

import { makeEvent } from '../test/fixtures'
import { json, makeMe, mockApi, renderWithAuth } from '../test/utils'
import { EventsPage } from './EventsPage'

function Keyed() {
  const location = useLocation()
  return <EventsPage key={location.search} />
}

function render(path = '/events') {
  return renderWithAuth(
    <Routes>
      <Route path="/events" element={<Keyed />} />
    </Routes>,
    path,
  )
}

const detail = {
  ...makeEvent(),
  referrer: null, http_version: 'HTTP/1.1', attributes: { request_time: '0.01' }, file_id: 1,
  filename: 'access.log', line_number: 42, job_id: 3,
  alerts: [{ id: 11, rule_id: 'ST-WEB-001', title: 'SQL injection indicators from 203.0.113.10', severity: 'high', status: 'new', indicator: 'union_select' }],
}

describe('EventsPage', () => {
  it('sends URL filters to the API and shows the count', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/events': () => json(200, { items: [makeEvent()], next_cursor: null, count: 1, count_capped: false }),
    })
    render('/events?source_ip=203.0.113.10&http_status=5xx')
    expect(await screen.findByText(/1 matching events/)).toBeInTheDocument()
    const call = calls.find((c) => c.url.startsWith('/api/events'))!
    expect(call.url).toContain('source_ip=203.0.113.10')
    expect(call.url).toContain('http_status=5xx')
    expect(screen.getByLabelText('Source IP or CIDR')).toHaveValue('203.0.113.10')
  })

  it('applies filters from the form into the URL', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/events': () => json(200, { items: [], next_cursor: null, count: 0, count_capped: false }),
    })
    render()
    await screen.findByText('No events match these filters.')
    await userEvent.type(screen.getByLabelText('Search raw log line'), 'sqlmap')
    await userEvent.selectOptions(screen.getByLabelText('Detection status'), 'true')
    await userEvent.click(screen.getByRole('button', { name: 'Apply filters' }))
    await screen.findByText('No events match these filters.')
    const last = calls.filter((c) => c.url.startsWith('/api/events')).at(-1)!
    expect(last.url).toContain('q=sqlmap')
    expect(last.url).toContain('flagged=true')
  })

  it('pages with cursors forward and back', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/events': (c) =>
        c.url.includes('cursor=abc')
          ? json(200, { items: [makeEvent({ id: 400, path: '/page-two' })], next_cursor: null, count: 2, count_capped: false })
          : json(200, { items: [makeEvent()], next_cursor: 'abc', count: 2, count_capped: false }),
    })
    render()
    await userEvent.click(await screen.findByRole('button', { name: 'Older →' }))
    expect(await screen.findByText(/\/page-two/)).toBeInTheDocument()
    expect(screen.getByText(/page 2/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '← Newer' }))
    expect(await screen.findByText(/page 1/)).toBeInTheDocument()
    expect(calls.filter((c) => c.url.startsWith('/api/events'))).toHaveLength(3)
  })

  it('opens event detail with raw line, attributes and linked alerts', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/events': () => json(200, { items: [makeEvent()], next_cursor: null, count: 1, count_capped: false }),
      'GET /api/events/501': () => json(200, detail),
    })
    render()
    await userEvent.click(await screen.findByRole('button', { name: 'Open event 501' }))
    const panel = await screen.findByRole('complementary', { name: 'Event 501' })
    expect(await within(panel).findByText(/sqlmap\/1.7"$/)).toBeInTheDocument()
    expect(within(panel).getByText('access.log : 42')).toBeInTheDocument()
    expect(within(panel).getByText(/"request_time": "0.01"/)).toBeInTheDocument()
    expect(within(panel).getByRole('link', { name: /SQL injection indicators/ })).toHaveAttribute('href', '/alerts/11')
  })

  it('shows API validation errors', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/events': () => json(422, { detail: 'source_ip must be an IP address or CIDR network' }),
    })
    render('/events?source_ip=nope')
    expect(await screen.findByRole('alert')).toHaveTextContent('source_ip must be an IP address or CIDR network')
  })
})
