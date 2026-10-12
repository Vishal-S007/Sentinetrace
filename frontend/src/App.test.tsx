import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import App from './App'
import { json, makeMe, mockApi, renderWithAuth, setCsrfCookie } from './test/utils'

const healthy = {
  'GET /api/health': () => json(200, { status: 'ok', version: '0.1.0' }),
  'GET /api/ready': () => json(200, { status: 'ready', database: 'ok' }),
}

describe('App authentication flow', () => {
  it('redirects anonymous users to the login page', async () => {
    mockApi({ 'GET /api/auth/me': () => json(401, { detail: 'Not authenticated' }) })
    renderWithAuth(<App />, '/admin/users')
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeInTheDocument()
  })

  it('logs in and lands on the originally requested page', async () => {
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(401, { detail: 'Not authenticated' }),
      'POST /api/auth/login': () => json(200, makeMe('admin')),
      ...healthy,
    })
    renderWithAuth(<App />, '/status')
    await userEvent.type(await screen.findByLabelText('Username'), 'adminuser')
    await userEvent.type(screen.getByLabelText('Password'), 'a-long-password')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(await screen.findByRole('heading', { name: 'System status' })).toBeInTheDocument()
    const loginCall = calls.find((c) => c.url === '/api/auth/login')!
    expect(loginCall.body).toEqual({ username: 'adminuser', password: 'a-long-password' })
  })

  it('shows a generic error for bad credentials and clears the password', async () => {
    mockApi({
      'GET /api/auth/me': () => json(401, {}),
      'POST /api/auth/login': () => json(401, { detail: 'Invalid username or password' }),
    })
    renderWithAuth(<App />, '/login')
    await userEvent.type(await screen.findByLabelText('Username'), 'x')
    await userEvent.type(screen.getByLabelText('Password'), 'wrong')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid username or password.')
    expect(screen.getByLabelText('Password')).toHaveValue('')
  })

  it('explains rate limiting on 429', async () => {
    mockApi({
      'GET /api/auth/me': () => json(401, {}),
      'POST /api/auth/login': () => json(429, { detail: 'Too many failed login attempts.' }),
    })
    renderWithAuth(<App />, '/login')
    await userEvent.type(await screen.findByLabelText('Username'), 'x')
    await userEvent.type(screen.getByLabelText('Password'), 'y')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Too many failed attempts')
  })

  it('hides admin navigation from viewers and blocks direct access', async () => {
    mockApi({ 'GET /api/auth/me': () => json(200, makeMe('viewer')), ...healthy })
    renderWithAuth(<App />, '/admin/users')
    expect(await screen.findByText('Access denied')).toBeInTheDocument()
    const nav = screen.getByRole('navigation', { name: 'Main' })
    expect(nav).toHaveTextContent('System status')
    expect(nav).not.toHaveTextContent('Users & roles')
    expect(nav).not.toHaveTextContent('Audit log')
  })

  it('shows admin navigation to admins', async () => {
    mockApi({ 'GET /api/auth/me': () => json(200, makeMe('admin')), ...healthy })
    renderWithAuth(<App />, '/status')
    const nav = await screen.findByRole('navigation', { name: 'Main' })
    expect(nav).toHaveTextContent('Users & roles')
    expect(nav).toHaveTextContent('Audit log')
  })

  it('signs out with the CSRF header and returns to login', async () => {
    const token = setCsrfCookie('tok-123')
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'POST /api/auth/logout': () => new Response(null, { status: 204 }),
      ...healthy,
    })
    renderWithAuth(<App />, '/status')
    await screen.findByRole('heading', { name: 'System status' })
    await userEvent.click(screen.getAllByRole('button', { name: 'Sign out' })[0])
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeInTheDocument()
    const logoutCall = calls.find((c) => c.url === '/api/auth/logout')!
    expect(logoutCall.headers['X-CSRF-Token']).toBe(token)
  })

  it('returns to login with a notice when the session expires mid-use', async () => {
    let expired = false
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('admin')),
      'GET /api/users': () => (expired ? json(401, { detail: 'Not authenticated' }) : json(200, [])),
      'GET /api/roles': () => json(200, []),
      ...healthy,
    })
    renderWithAuth(<App />, '/status')
    await screen.findByRole('heading', { name: 'System status' })
    expired = true
    await userEvent.click(screen.getByRole('link', { name: 'Users & roles' }))
    await waitFor(() => expect(screen.getByText(/Your session has ended/)).toBeInTheDocument())
  })
})
