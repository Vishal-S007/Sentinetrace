import { useState, type FormEvent } from 'react'

import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { Button, ErrorBanner, Field, PageHeader, SuccessBanner, TextInput } from '../components/ui'

export function AccountPage() {
  const { state } = useAuth()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)
  const [busy, setBusy] = useState(false)

  if (state.status !== 'authenticated') return null
  const { user, permissions } = state.me

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setDone(false)
    if (next !== confirm) {
      setError('New passwords do not match.')
      return
    }
    setBusy(true)
    try {
      await api.changePassword(current, next)
      setDone(true)
      setCurrent('')
      setNext('')
      setConfirm('')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unexpected error')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="max-w-2xl">
      <PageHeader title="My account" />
      <dl className="mb-8 grid grid-cols-[8rem_1fr] gap-y-2 rounded-md border border-line bg-panel p-4 text-sm">
        <dt className="text-ink-dim">Username</dt>
        <dd className="font-mono">{user.username}</dd>
        <dt className="text-ink-dim">Role</dt>
        <dd className="capitalize">{user.role}</dd>
        <dt className="text-ink-dim">Permissions</dt>
        <dd className="font-mono text-xs text-ink-dim">{permissions.join(', ')}</dd>
      </dl>

      <form onSubmit={submit} aria-label="Change password" className="space-y-3 rounded-md border border-line bg-panel p-4" noValidate>
        <h2 className="text-sm font-semibold">Change password</h2>
        <p className="text-xs text-ink-dim">Changing your password signs out all your other sessions.</p>
        {error && <ErrorBanner message={error} />}
        {done && <SuccessBanner message="Password changed. Other sessions were signed out." />}
        <Field label="Current password">
          <TextInput type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
        </Field>
        <Field label="New password" hint="At least 12 characters">
          <TextInput type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
        </Field>
        <Field label="Confirm new password">
          <TextInput type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </Field>
        <Button type="submit" variant="primary" disabled={busy || !current || !next || !confirm}>
          {busy ? 'Saving…' : 'Change password'}
        </Button>
      </form>
    </section>
  )
}
