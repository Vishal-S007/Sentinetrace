import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { StatusPage } from './StatusPage'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function mockFetch(routes: Record<string, () => Response | Promise<Response>>) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const handler = routes[url]
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
    expect(spy).toHaveBeenCalledTimes(4)
  })
})
