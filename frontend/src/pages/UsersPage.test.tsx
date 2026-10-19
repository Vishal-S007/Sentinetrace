import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import type { User } from '../api/client'
import { json, makeMe, mockApi, permissionsByRole, renderWithAuth, setCsrfCookie } from '../test/utils'
import { UsersPage } from './UsersPage'

const me = makeMe('admin', 1)
const other: User = {
  id: 2,
  username: 'bob',
  email: 'bob@example.com',
  role: 'viewer',
  is_active: true,
  created_at: '2026-10-01T00:00:00Z',
  last_login_at: null,
}
const roles = [
  { name: 'viewer', description: 'Read-only', permissions: permissionsByRole.viewer },
  { name: 'analyst', description: 'Investigate', permissions: permissionsByRole.analyst },
  { name: 'admin', description: 'Everything', permissions: permissionsByRole.admin },
]

function base(extra: Record<string, Parameters<typeof mockApi>[0][string]> = {}) {
  return mockApi({
    'GET /api/auth/me': () => json(200, me),
    'GET /api/users': () => json(200, [me.user, other]),
    'GET /api/roles': () => json(200, roles),
    ...extra,
  })
}

describe('UsersPage', () => {
  it('lists users and role permissions; own row cannot be changed', async () => {
    base()
    renderWithAuth(<UsersPage />)
    const bobRow = (await screen.findByText('bob')).closest('tr')!
    expect(within(bobRow).getByText('bob@example.com')).toBeInTheDocument()
    expect(within(bobRow).getByRole('button', { name: 'Disable' })).toBeEnabled()

    const selfRow = screen.getByText('(you)').closest('tr')!
    expect(within(selfRow).getByRole('combobox')).toBeDisabled()
    expect(within(selfRow).queryByRole('button', { name: 'Disable' })).not.toBeInTheDocument()
    expect(screen.getByText('Role permissions')).toBeInTheDocument()
  })

  it('shows a loading state, then an error state when the API fails', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, me),
      'GET /api/users': () => json(500, { detail: 'Internal server error' }),
      'GET /api/roles': () => json(200, roles),
    })
    renderWithAuth(<UsersPage />)
    expect(screen.getByRole('status')).toHaveTextContent('Loading users')
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load users: Internal server error')
  })

  it('creates a user with the CSRF header and shows it in the list', async () => {
    const token = setCsrfCookie('csrf-abc')
    const created: User = { ...other, id: 3, username: 'carol', email: null, role: 'analyst' }
    const { calls } = base({ 'POST /api/users': () => json(201, created) })
    renderWithAuth(<UsersPage />)
    await screen.findByText('bob')

    const form = screen.getByRole('form', { name: 'Create user' })
    await userEvent.type(within(form).getByLabelText(/Username/), 'carol')
    await userEvent.type(within(form).getByLabelText(/Initial password/), 'a-strong-password')
    await userEvent.selectOptions(within(form).getByLabelText('Role'), 'analyst')
    await userEvent.click(within(form).getByRole('button', { name: 'Create user' }))

    expect(await screen.findByText('User carol created.')).toBeInTheDocument()
    expect(screen.getByText('carol')).toBeInTheDocument()
    const post = calls.find((c) => c.method === 'POST')!
    expect(post.body).toEqual({ username: 'carol', email: null, password: 'a-strong-password', role: 'analyst' })
    expect(post.headers['X-CSRF-Token']).toBe(token)
  })

  it('shows server validation errors from user creation', async () => {
    base({
      'POST /api/users': () =>
        json(422, { detail: [{ loc: ['body', 'password'], msg: 'String should have at least 12 characters' }] }),
    })
    renderWithAuth(<UsersPage />)
    await screen.findByText('bob')
    const form = screen.getByRole('form', { name: 'Create user' })
    await userEvent.type(within(form).getByLabelText(/Username/), 'dave')
    await userEvent.type(within(form).getByLabelText(/Initial password/), 'short')
    await userEvent.click(within(form).getByRole('button', { name: 'Create user' }))
    expect(await within(form).findByRole('alert')).toHaveTextContent('password: String should have at least 12 characters')
  })

  it('disables a user and changes a role', async () => {
    const { calls } = base({
      'PATCH /api/users/2': (call) => json(200, { ...other, ...(call.body as object) }),
    })
    renderWithAuth(<UsersPage />)
    const row = (await screen.findByText('bob')).closest('tr')!

    await userEvent.click(within(row).getByRole('button', { name: 'Disable' }))
    expect(await screen.findByText(/bob disabled; their sessions were ended/)).toBeInTheDocument()
    expect(within(row).getByText('Disabled')).toBeInTheDocument()

    await userEvent.selectOptions(within(row).getByRole('combobox'), 'analyst')
    expect(await screen.findByText('Role of bob changed to analyst.')).toBeInTheDocument()
    expect(calls.filter((c) => c.method === 'PATCH').map((c) => c.body)).toEqual([{ is_active: false }, { role: 'analyst' }])
  })
})

describe('UsersPage: erasure', () => {
  it('shows a pending deletion request and erases after typing the username', async () => {
    const csrf = setCsrfCookie()
    const requested = { ...other, deletion_requested_at: '2026-10-18T08:00:00Z' }
    const { calls } = mockApi({
      'GET /api/auth/me': () => json(200, me),
      'GET /api/users': () => json(200, [me.user, requested]),
      'GET /api/roles': () => json(200, roles),
      'POST /api/users/2/erase': () =>
        json(200, { ...other, username: 'erased-user-2', email: null, is_active: false, deletion_requested_at: null }),
    })
    renderWithAuth(<UsersPage />)
    const row = (await screen.findByText('bob')).closest('tr')!
    expect(within(row).getByText(/Deletion requested/)).toBeInTheDocument()

    await userEvent.click(within(row).getByRole('button', { name: 'Erase data' }))
    const form = screen.getByRole('form', { name: 'Erase personal data of bob' })
    const submit = within(form).getByRole('button', { name: 'Erase personal data' })
    expect(submit).toBeDisabled()
    await userEvent.type(within(form).getByLabelText('Type bob to confirm'), 'bob')
    await userEvent.click(submit)

    expect(await screen.findByText(/Personal data of bob erased/)).toBeInTheDocument()
    const erase = calls.find((c) => c.url === '/api/users/2/erase')!
    expect(erase.body).toEqual({ confirm_username: 'bob' })
    expect(erase.headers['X-CSRF-Token']).toBe(csrf)
    const erasedRow = screen.getByText('erased-user-2').closest('tr')!
    expect(within(erasedRow).getByText('Erased')).toBeInTheDocument()
    expect(within(erasedRow).queryByRole('button', { name: 'Erase data' })).not.toBeInTheDocument()
    expect(within(erasedRow).getByRole('combobox')).toBeDisabled()
  })
})
