import { useCallback, useEffect, useState, type FormEvent } from 'react'

import { api, ApiError, type Role, type RoleName, type User } from '../api/client'
import { formatDateTime } from '../lib/format'
import { useAuth } from '../auth/AuthContext'
import {
  Button,
  Empty,
  ErrorBanner,
  Field,
  Loading,
  PageHeader,
  Select,
  SuccessBanner,
  TextInput,
} from '../components/ui'

type LoadState = { kind: 'loading' } | { kind: 'error'; message: string } | { kind: 'loaded'; users: User[]; roles: Role[] }

const ROLES: RoleName[] = ['viewer', 'analyst', 'admin']

function errorMessage(err: unknown): string {
  return err instanceof ApiError ? err.message : 'Unexpected error'
}

async function fetchData(): Promise<LoadState> {
  try {
    const [users, roles] = await Promise.all([api.users(), api.roles()])
    return { kind: 'loaded', users, roles }
  } catch (err) {
    return { kind: 'error', message: errorMessage(err) }
  }
}

function CreateUserForm({ onCreated }: { onCreated: (u: User) => void }) {
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<RoleName>('viewer')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const user = await api.createUser({ username, email: email || null, password, role })
      setUsername('')
      setEmail('')
      setPassword('')
      setRole('viewer')
      onCreated(user)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} aria-label="Create user" className="mb-6 space-y-3 rounded-md border border-line bg-panel p-4" noValidate>
      <h2 className="text-sm font-semibold">Add user</h2>
      {error && <ErrorBanner message={error} />}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Field label="Username" hint="3–64 chars: letters, digits, . _ -">
          <TextInput value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" />
        </Field>
        <Field label="Email (optional)">
          <TextInput type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" />
        </Field>
        <Field label="Initial password" hint="At least 12 characters">
          <TextInput type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
        </Field>
        <Field label="Role">
          <Select value={role} onChange={(e) => setRole(e.target.value as RoleName)}>
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </Select>
        </Field>
      </div>
      <Button type="submit" variant="primary" disabled={busy || !username || !password}>
        {busy ? 'Creating…' : 'Create user'}
      </Button>
    </form>
  )
}

function UserRow({ user, isSelf, onChanged, onError }: {
  user: User
  isSelf: boolean
  onChanged: (u: User, msg: string) => void
  onError: (msg: string) => void
}) {
  const [busy, setBusy] = useState(false)

  async function update(body: Parameters<typeof api.updateUser>[1], msg: string) {
    setBusy(true)
    try {
      onChanged(await api.updateUser(user.id, body), msg)
    } catch (err) {
      onError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <tr className="border-t border-line">
      <td className="px-3 py-2 font-mono text-sm">
        {user.username}
        {isSelf && <span className="ml-2 text-xs text-ink-dim">(you)</span>}
      </td>
      <td className="px-3 py-2 text-sm text-ink-dim">{user.email ?? '—'}</td>
      <td className="px-3 py-2">
        <Select
          aria-label={`Role for ${user.username}`}
          value={user.role}
          disabled={busy || isSelf}
          onChange={(e) => void update({ role: e.target.value as RoleName }, `Role of ${user.username} changed to ${e.target.value}.`)}
        >
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </Select>
      </td>
      <td className="px-3 py-2 text-sm">
        <span className={user.is_active ? 'text-ok' : 'text-ink-dim'}>{user.is_active ? 'Active' : 'Disabled'}</span>
      </td>
      <td className="px-3 py-2 text-sm text-ink-dim">{formatDateTime(user.last_login_at)}</td>
      <td className="px-3 py-2 text-right">
        {!isSelf && (
          <Button
            variant={user.is_active ? 'danger' : 'secondary'}
            disabled={busy}
            onClick={() =>
              void update(
                { is_active: !user.is_active },
                `${user.username} ${user.is_active ? 'disabled; their sessions were ended' : 'enabled'}.`,
              )
            }
          >
            {user.is_active ? 'Disable' : 'Enable'}
          </Button>
        )}
      </td>
    </tr>
  )
}

export function UsersPage() {
  const { state: auth } = useAuth()
  const selfId = auth.status === 'authenticated' ? auth.me.user.id : -1
  const [state, setState] = useState<LoadState>({ kind: 'loading' })
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null)

  useEffect(() => {
    let active = true
    void fetchData().then((s) => active && setState(s))
    return () => {
      active = false
    }
  }, [])

  const replaceUser = useCallback((u: User, msg: string) => {
    setState((s) => (s.kind === 'loaded' ? { ...s, users: s.users.map((x) => (x.id === u.id ? u : x)) } : s))
    setNotice({ ok: true, text: msg })
  }, [])

  return (
    <section>
      <PageHeader title="Users & roles" subtitle="Manage who can access SentinelTrace and what they can do." />
      <CreateUserForm
        onCreated={(u) => {
          setState((s) => (s.kind === 'loaded' ? { ...s, users: [...s.users, u].sort((a, b) => a.username.localeCompare(b.username)) } : s))
          setNotice({ ok: true, text: `User ${u.username} created.` })
        }}
      />
      {notice && <div className="mb-4">{notice.ok ? <SuccessBanner message={notice.text} /> : <ErrorBanner message={notice.text} />}</div>}

      {state.kind === 'loading' && <Loading label="Loading users…" />}
      {state.kind === 'error' && <ErrorBanner message={`Could not load users: ${state.message}`} />}
      {state.kind === 'loaded' && (
        <>
          {state.users.length === 0 ? (
            <Empty>No users yet.</Empty>
          ) : (
            <div className="overflow-x-auto rounded-md border border-line">
              <table className="w-full min-w-[720px] text-left">
                <thead className="bg-panel text-xs uppercase tracking-wide text-ink-dim">
                  <tr>
                    <th className="px-3 py-2">Username</th>
                    <th className="px-3 py-2">Email</th>
                    <th className="px-3 py-2">Role</th>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2">Last login</th>
                    <th className="px-3 py-2" aria-label="Actions" />
                  </tr>
                </thead>
                <tbody>
                  {state.users.map((u) => (
                    <UserRow
                      key={u.id}
                      user={u}
                      isSelf={u.id === selfId}
                      onChanged={replaceUser}
                      onError={(text) => setNotice({ ok: false, text })}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <h2 className="mb-2 mt-8 text-sm font-semibold">Role permissions</h2>
          <div className="grid gap-3 md:grid-cols-3">
            {state.roles.map((r) => (
              <div key={r.name} className="rounded-md border border-line bg-panel p-3">
                <p className="font-medium capitalize">{r.name}</p>
                <p className="mb-2 text-xs text-ink-dim">{r.description}</p>
                <ul className="flex flex-wrap gap-1">
                  {r.permissions.map((p) => (
                    <li key={p} className="rounded bg-panel-2 px-1.5 py-0.5 font-mono text-[11px] text-ink-dim">
                      {p}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </>
      )}
    </section>
  )
}
