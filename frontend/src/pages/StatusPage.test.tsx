import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { makeMe, renderWithAuth } from '../test/utils'
import { StatusPage } from './StatusPage'

let role: 'viewer' | 'admin' = 'viewer'
const render = (ui: React.ReactElement) => renderWithAuth(ui, '/status')

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function mockFetch(routes: Record<string, () => Response | Promise<Response>>) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const handler = url === '/api/auth/me' ? () => jsonResponse(200, makeMe(role)) : routes[url]
    if (!handler) throw new Error(`Unmocked request: ${url}`)
    return handler()
  })
}

describe('StatusPage', () => {
  it('shows a loading state first, then healthy status', async () => {
    mockFetch({
      '/api/health': () => jsonResponse(200, { status: 'ok', version: '0.1.0' }),
      '/api/ready': () => jsonResponse(200, { status: 'ready', database: 'ok' }),
    })
    render(<StatusPage />)
    expect(screen.getByRole('status')).toHaveTextContent('Checking API health')
    expect(await screen.findByText('Online')).toBeInTheDocument()
    expect(screen.getByText('Connected')).toBeInTheDocument()
    expect(screen.getByText('0.1.0')).toBeInTheDocument()
  })

  it('treats a 503 readiness response as database unavailable, not an error', async () => {
    mockFetch({
      '/api/health': () => jsonResponse(200, { status: 'ok', version: '0.1.0' }),
      '/api/ready': () => jsonResponse(503, { status: 'not_ready', database: 'unavailable' }),
    })
    render(<StatusPage />)
    expect(await screen.findByText('Unavailable')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('shows an error state when the API cannot be reached', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('Failed to fetch'))
    render(<StatusPage />)
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('API unreachable')
    expect(alert).toHaveTextContent('Cannot reach the SentinelTrace API')
  })

  it('shows the server error message on a 500', async () => {
    mockFetch({
      '/api/health': () => jsonResponse(500, { detail: 'Internal server error' }),
      '/api/ready': () => jsonResponse(200, { status: 'ready', database: 'ok' }),
    })
    render(<StatusPage />)
    expect(await screen.findByRole('alert')).toHaveTextContent('Internal server error')
  })

  it('re-check button performs a new request and recovers from an error', async () => {
    let healthy = false
    const spy = mockFetch({
      '/api/health': () =>
        healthy
          ? jsonResponse(200, { status: 'ok', version: '0.1.0' })
          : jsonResponse(500, { detail: 'Internal server error' }),
      '/api/ready': () => jsonResponse(200, { status: 'ready', database: 'ok' }),
    })
    render(<StatusPage />)
    await screen.findByRole('alert')
    healthy = true
    await userEvent.click(screen.getByRole('button', { name: /re-check/i }))
    expect(await screen.findByText('Online')).toBeInTheDocument()
    expect(spy.mock.calls.filter(([u]) => u === '/api/health')).toHaveLength(2)
  })
})

describe('StatusPage settings (admin)', () => {
  it('shows effective settings and system health, without secrets', async () => {
    role = 'admin'
    mockFetch({
      '/api/health': () => jsonResponse(200, { status: 'ok', version: '0.1.0' }),
      '/api/ready': () => jsonResponse(200, { status: 'ready', database: 'ok' }),
      '/api/admin/system': () =>
        jsonResponse(200, {
          settings: [
            { group: 'Uploads and ingestion', key: 'max_upload_bytes', env: 'ST_MAX_UPLOAD_BYTES', value: 52428800, description: 'Largest accepted upload (bytes)' },
            { group: 'Sessions and sign-in', key: 'cookie_secure', env: 'ST_COOKIE_SECURE', value: false, description: 'Cookies sent over HTTPS only' },
            { group: 'Retention and limits', key: 'retention_auto_days', env: 'ST_RETENTION_AUTO_DAYS', value: null, description: 'Automatic purge' },
          ],
          database: { host: 'db:5432', name: 'sentineltrace', server_version: '16.4', size_bytes: 10485760, rows: { events: 6620, alerts: 13, audit_log: 40 } },
          queue: { jobs_queued: 1, jobs_running: 0, jobs_failed: 2, runs_queued: 0, runs_running: 0, last_import_finished_at: null, last_detection_finished_at: null },
          storage: { files: 3, bytes: 2048, free_bytes: 50, total_bytes: 100 },
        }),
    })
    render(<StatusPage />)
    const settings = await screen.findByRole('region', { name: 'Application settings' })
    expect(settings).toHaveTextContent('Largest accepted upload (bytes)52,428,800ST_MAX_UPLOAD_BYTES')
    expect(settings).toHaveTextContent('Cookies sent over HTTPS onlynoST_COOKIE_SECURE')
    expect(settings).toHaveTextContent('Automatic purgenot set')
    const health = screen.getByRole('region', { name: 'Database, queue and storage' })
    expect(health).toHaveTextContent('sentineltrace on db:5432')
    expect(health).toHaveTextContent('Database size10 MB')
    expect(health).toHaveTextContent('6,620')
    expect(health).toHaveTextContent('50 B (50% used)')
    role = 'viewer'
  })

  it('is not shown to non-admins', async () => {
    role = 'viewer'
    mockFetch({
      '/api/health': () => jsonResponse(200, { status: 'ok', version: '0.1.0' }),
      '/api/ready': () => jsonResponse(200, { status: 'ready', database: 'ok' }),
    })
    render(<StatusPage />)
    await screen.findByText('Online')
    expect(screen.queryByRole('region', { name: 'Application settings' })).not.toBeInTheDocument()
  })
})
