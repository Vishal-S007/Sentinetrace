import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'

import { makeJob } from '../test/fixtures'
import { json, makeMe, mockApi, renderWithAuth } from '../test/utils'
import { JobDetailPage } from './JobDetailPage'

function renderPage() {
  return renderWithAuth(
    <Routes>
      <Route path="/jobs/:id" element={<JobDetailPage />} />
    </Routes>,
    '/jobs/7',
  )
}

const errors = {
  items: [
    { id: 1, line_number: 3, reason: 'invalid timestamp', raw_line: '<script>alert(1)</script>' },
    { id: 2, line_number: 9, reason: 'invalid JSON', raw_line: '{"broken' },
  ],
  next_after_id: null,
  total_rejected: 2,
  stored: 2,
  truncated: false,
}

describe('JobDetailPage', () => {
  it('shows counts and rejected lines as plain text with a CSV link', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/jobs/7': () => json(200, makeJob()),
      'GET /api/jobs/7/errors': () => json(200, errors),
    })
    renderPage()
    expect(await screen.findByRole('heading', { name: 'Job #7' })).toBeInTheDocument()
    expect(screen.getByText('Parsed events').nextSibling).toHaveTextContent('8')
    // Untrusted content is shown literally, not interpreted as HTML.
    expect(await screen.findByText('<script>alert(1)</script>')).toBeInTheDocument()
    expect(document.querySelector('script')).toBeNull()
    expect(screen.getByRole('link', { name: 'Download CSV' })).toHaveAttribute('href', '/api/jobs/7/errors.csv')
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
  })

  it('shows the failure reason and lets analysts retry', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/jobs/7': () => json(200, makeJob({ status: 'failed', parsed_count: 0, rejected_count: 0, error_message: 'The uploaded file is missing from storage.' })),
      'GET /api/jobs/7/errors': () => json(200, { ...errors, items: [], total_rejected: 0, stored: 0 }),
      'POST /api/jobs/7/retry': () => json(202, makeJob({ status: 'queued', parsed_count: 0, error_message: null })),
    })
    renderPage()
    expect(await screen.findByText('The uploaded file is missing from storage.')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('Waiting for a worker…')).toBeInTheDocument()
    expect(calls.some((c) => c.method === 'POST' && c.url === '/api/jobs/7/retry')).toBe(true)
  })

  it('viewers cannot retry failed jobs', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/jobs/7': () => json(200, makeJob({ status: 'failed', error_message: 'x' })),
      'GET /api/jobs/7/errors': () => json(200, errors),
    })
    renderPage()
    await screen.findByText('Processing failed')
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
  })

  it('shows not-found errors', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/jobs/7': () => json(404, { detail: 'Job not found' }),
    })
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('Job not found')
  })
})
