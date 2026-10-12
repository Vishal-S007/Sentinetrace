import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import { json, makeMe, mockApi, renderWithAuth } from '../test/utils'
import { AccountPage } from './AccountPage'

async function fill(current: string, next: string, confirm: string) {
  await userEvent.type(await screen.findByLabelText('Current password'), current)
  await userEvent.type(screen.getByLabelText(/^New password/), next)
  await userEvent.type(screen.getByLabelText('Confirm new password'), confirm)
  await userEvent.click(screen.getByRole('button', { name: 'Change password' }))
}

describe('AccountPage', () => {
  it('changes the password', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'POST /api/auth/password': () => new Response(null, { status: 204 }),
    })
    renderWithAuth(<AccountPage />)
    await fill('old-password-123', 'new-password-456', 'new-password-456')
    expect(await screen.findByText(/Password changed/)).toBeInTheDocument()
    expect(calls.at(-1)!.body).toEqual({ current_password: 'old-password-123', new_password: 'new-password-456' })
  })

  it('rejects mismatched confirmation without calling the API', async () => {
    const { calls } = mockApi({ 'GET /api/auth/me': () => json(200, makeMe('viewer')) })
    renderWithAuth(<AccountPage />)
    await fill('old-password-123', 'new-password-456', 'different-789')
    expect(await screen.findByRole('alert')).toHaveTextContent('New passwords do not match.')
    expect(calls.some((c) => c.url === '/api/auth/password')).toBe(false)
  })

  it('shows the server error for a wrong current password', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('viewer')),
      'POST /api/auth/password': () => json(400, { detail: 'Current password is incorrect' }),
    })
    renderWithAuth(<AccountPage />)
    await fill('wrong-password', 'new-password-456', 'new-password-456')
    expect(await screen.findByRole('alert')).toHaveTextContent('Current password is incorrect')
  })
})
