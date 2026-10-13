import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import { makeDashboard } from '../test/fixtures'
import { json, makeMe, mockApi, renderWithAuth } from '../test/utils'
import { DashboardPage } from './DashboardPage'

describe('DashboardPage', () => {
  it('shows live totals with drill-down links', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/dashboard': () => json(200, makeDashboard()),
    })
    renderWithAuth(<DashboardPage />, '/dashboard')
    const open = await screen.findByRole('link', { name: /Open alerts\s*12/ })
    expect(open).toHaveAttribute('href', '/alerts?status=new')
    expect(screen.getByRole('link', { name: /Events in range\s*6,620/ })).toHaveAttribute('href', '/events')

    const ips = screen.getByRole('region', { name: 'Top source IPs by alerts' })
    expect(within(ips).getByRole('link', { name: '203.0.113.60' })).toHaveAttribute('href', '/alerts?source_ip=203.0.113.60')
    expect(within(ips).getByRole('link', { name: '67' })).toHaveAttribute('href', '/events?source_ip=203.0.113.60')

    const sev = screen.getByRole('region', { name: 'Alerts by severity' })
    expect(within(sev).getByRole('link', { name: /Medium\s*8/ })).toHaveAttribute('href', '/alerts?severity=medium')
    expect(screen.getByRole('link', { name: /Repeated authentication failures/ })).toHaveAttribute('href', '/alerts?rule_id=ST-AUTH-001')
    expect(screen.getByRole('link', { name: /Potential brute force/ })).toHaveAttribute('href', '/alerts/38')
    expect(screen.getByRole('link', { name: /web_access.log/ })).toHaveAttribute('href', '/jobs/3')
  })

  it('changes the time range and re-queries', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/dashboard': () => json(200, makeDashboard()),
    })
    renderWithAuth(<DashboardPage />, '/dashboard')
    await screen.findByRole('region', { name: 'Alerts by severity' })
    await userEvent.click(screen.getByRole('button', { name: '30 days' }))
    await screen.findByRole('region', { name: 'Alerts by severity' })
    expect(calls.filter((c) => c.url.startsWith('/api/dashboard')).map((c) => c.url)).toEqual([
      '/api/dashboard?range=7d',
      '/api/dashboard?range=30d',
    ])
    expect(screen.getByRole('button', { name: '30 days' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('offers "all time" when the range is empty but data exists', async () => {
    const empty = makeDashboard({
      totals: { events: 0, alerts: 0, open_alerts: 0, high_open_alerts: 0, sources: 3, files: 3 },
      events_over_time: [],
      alerts_over_time: [],
      top_source_ips: [],
      top_rules: [],
      recent_high_alerts: [],
    })
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/dashboard': (c) => json(200, c.url.includes('range=all') ? makeDashboard({ range: 'all' }) : empty),
    })
    renderWithAuth(<DashboardPage />, '/dashboard')
    const hint = await screen.findByText(/No events in the last 7 days/)
    expect(screen.getByText('No alerts with a source IP in this range.')).toBeInTheDocument()
    await userEvent.click(within(hint).getByRole('button', { name: 'Show all time' }))
    expect(await screen.findByRole('link', { name: '203.0.113.60' })).toBeInTheDocument()
    expect(calls.at(-1)!.url).toBe('/api/dashboard?range=all')
  })

  it('shows an error state', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/dashboard': () => json(500, { detail: 'Internal server error' }),
    })
    renderWithAuth(<DashboardPage />, '/dashboard')
    expect(screen.getByRole('status')).toHaveTextContent('Loading overview')
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load the overview')
  })
})
