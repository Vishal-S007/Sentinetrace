import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'

import { makeRule } from '../test/fixtures'
import { json, makeMe, mockApi, renderWithAuth, setCsrfCookie } from '../test/utils'
import { RuleDetailPage } from './RuleDetailPage'
import { RulesPage } from './RulesPage'

function renderDetail() {
  return renderWithAuth(
    <Routes>
      <Route path="/rules/:id" element={<RuleDetailPage />} />
    </Routes>,
    '/rules/ST-AUTH-001',
  )
}

describe('RulesPage', () => {
  it('lists rules and lets admins re-run detection', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('admin')),
      'GET /api/rules': () => json(200, [makeRule(), makeRule({ rule_id: 'ST-WEB-004', name: 'Request burst', enabled: false, open_alerts: 0 })]),
      'GET /api/detection/runs': () => json(200, []),
      'POST /api/detection/runs': () => json(202, { id: 4, status: 'queued' }),
    })
    renderWithAuth(<RulesPage />, '/rules')
    expect(await screen.findByRole('link', { name: 'Repeated authentication failures' })).toHaveAttribute('href', '/rules/ST-AUTH-001')
    expect(screen.getByText('Disabled')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '3' })).toHaveAttribute('href', '/alerts?rule_id=ST-AUTH-001&status=new')
    await userEvent.click(screen.getByRole('button', { name: 'Re-run detection' }))
    expect(await screen.findByText(/Detection run #4 queued/)).toBeInTheDocument()
    expect(calls.some((c) => c.method === 'POST' && c.url === '/api/detection/runs')).toBe(true)
  })

  it('does not offer re-runs to analysts', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/rules': () => json(200, [makeRule()]),
    })
    renderWithAuth(<RulesPage />, '/rules')
    await screen.findByRole('link', { name: 'Repeated authentication failures' })
    expect(screen.queryByRole('button', { name: 'Re-run detection' })).not.toBeInTheDocument()
  })
})

describe('RuleDetailPage', () => {
  it('shows version history with what changed', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'GET /api/rules/ST-AUTH-001': () => json(200, makeRule()),
    })
    renderDetail()
    const history = await screen.findByRole('region', { name: 'Version history' })
    expect(within(history).getByText('Threshold:', { exact: false })).toHaveTextContent('Threshold: 8 → 5')
    expect(within(history).getByText('“tuned”')).toBeInTheDocument()
    // Viewers see settings but cannot change them.
    expect(screen.getByText('Only administrators can change rule settings.')).toBeInTheDocument()
    expect(screen.getByLabelText(/^Threshold/)).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Save new version' })).not.toBeInTheDocument()
  })

  it('saves a new version with typed config values', async () => {
    setCsrfCookie('tok')
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('admin')),
      'GET /api/rules/ST-AUTH-001': () => json(200, makeRule()),
      'PATCH /api/rules/ST-AUTH-001': () => json(200, makeRule({ version: 3, config: { threshold: 10, window_seconds: 300 } })),
    })
    renderDetail()
    const threshold = await screen.findByLabelText(/^Threshold/)
    const save = screen.getByRole('button', { name: 'Save new version' })
    expect(save).toBeDisabled()
    await userEvent.clear(threshold)
    await userEvent.type(threshold, '10')
    await userEvent.selectOptions(screen.getByLabelText(/Severity/), 'high')
    await userEvent.type(screen.getByLabelText(/Change note/), 'fewer false positives')
    await userEvent.click(save)
    expect(await screen.findByText('Saved as version 3.')).toBeInTheDocument()
    const patch = calls.find((c) => c.method === 'PATCH')!
    expect(patch.body).toEqual({
      enabled: true,
      severity: 'high',
      config: { threshold: 10, window_seconds: 300 },
      note: 'fewer false positives',
    })
    expect(patch.headers['X-CSRF-Token']).toBe('tok')
  })

  it('shows validation errors from the server', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('admin')),
      'GET /api/rules/ST-AUTH-001': () => json(200, makeRule()),
      'PATCH /api/rules/ST-AUTH-001': () =>
        json(422, { detail: [{ loc: ['body', 'config', 'threshold'], msg: 'Input should be greater than or equal to 2' }] }),
    })
    renderDetail()
    const threshold = await screen.findByLabelText(/^Threshold/)
    await userEvent.clear(threshold)
    await userEvent.type(threshold, '3')
    await userEvent.click(screen.getByRole('button', { name: 'Save new version' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('threshold: Input should be greater than or equal to 2')
  })
})
