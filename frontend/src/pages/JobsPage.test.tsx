import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { makeJob } from '../test/fixtures'
import { json, makeMe, mockApi, renderWithAuth } from '../test/utils'
import { JobsPage } from './JobsPage'

afterEach(() => vi.useRealTimers())

describe('JobsPage', () => {
  it('lists jobs with counts and links', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/jobs': () => json(200, { items: [makeJob({ status: 'completed_with_errors' })], next_before_id: null }),
    })
    renderWithAuth(<JobsPage />, '/jobs')
    expect(await screen.findByRole('link', { name: '#7' })).toHaveAttribute('href', '/jobs/7')
    const table = screen.getByRole('table')
    expect(within(table).getByText('Completed with errors')).toBeInTheDocument()
    expect(within(table).getByText('access.log')).toBeInTheDocument()
  })

  it('filters by status via the query string', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/jobs': () => json(200, { items: [], next_before_id: null }),
    })
    renderWithAuth(<JobsPage />, '/jobs')
    await screen.findByText(/No jobs match/)
    await userEvent.selectOptions(screen.getByLabelText('Filter by status'), 'failed')
    await waitFor(() => expect(calls.at(-1)!.url).toContain('status=failed'))
  })

  it('polls while a job is queued and stops when it finishes', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    let n = 0
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/jobs': () => {
        n += 1
        return json(200, { items: [makeJob({ status: n < 3 ? 'running' : 'completed' })], next_before_id: null })
      },
    })
    renderWithAuth(<JobsPage />, '/jobs')
    expect(await within(await screen.findByRole('table')).findByText('Running')).toBeInTheDocument()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2100)
    })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2100)
    })
    expect(await within(screen.getByRole('table')).findByText('Completed')).toBeInTheDocument()
    const count = calls.filter((c) => c.url.startsWith('/api/jobs')).length
    await act(async () => {
      await vi.advanceTimersByTimeAsync(6000)
    })
    expect(calls.filter((c) => c.url.startsWith('/api/jobs')).length).toBe(count)
  })

  it('shows an error state', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/jobs': () => json(500, { detail: 'Internal server error' }),
    })
    renderWithAuth(<JobsPage />, '/jobs')
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load jobs')
  })
})
