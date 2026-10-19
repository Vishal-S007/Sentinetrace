import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'

import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { Button, ErrorBanner, Field, PageHeader, SuccessBanner, TextInput } from '../components/ui'
import { formatDateTime } from '../lib/format'

function YourData({ requestedAt }: { requestedAt: string | null }) {
  const [pending, setPending] = useState<string | null>(requestedAt)
  const [confirming, setConfirming] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit() {
    setBusy(true)
    setError(null)
    try {
      setPending((await api.requestDeletion()).requested_at)
      setConfirming(false)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unexpected error')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section aria-label="Your data" className="mt-8 space-y-3 rounded-md border border-line bg-panel p-4 text-sm">
      <h2 className="font-semibold">Your data</h2>
      <p className="text-ink-dim">
        SentinelTrace keeps your account details, sign-in records and an audit trail of your actions. The{' '}
        <Link to="/legal/privacy" className="text-accent underline underline-offset-2">
          privacy policy
        </Link>{' '}
        explains what is kept, for how long, and your rights.
      </p>
      {error && <ErrorBanner message={error} />}
      {pending ? (
        <p role="status" className="rounded-md border border-warn/40 bg-warn/10 p-3 text-warn">
          You asked for your data to be deleted on {formatDateTime(pending)}. An administrator will erase your account.
          You can keep using it until then.
        </p>
      ) : confirming ? (
        <div className="space-y-3 rounded-md border border-line p-3">
          <p>
            An administrator will erase your account. Your username and email will be removed, you will be signed out for
            good, and your sign-in records will be deleted. Past audit log entries are kept as a security record.
          </p>
          <div className="flex gap-2">
            <Button variant="danger" disabled={busy} onClick={() => void submit()}>
              {busy ? 'Sending…' : 'Send deletion request'}
            </Button>
            <Button onClick={() => setConfirming(false)}>Cancel</Button>
          </div>
        </div>
      ) : (
        <Button onClick={() => setConfirming(true)}>Request deletion of my data</Button>
      )}
    </section>
  )
}

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
      <YourData requestedAt={user.deletion_requested_at ?? null} />
    </section>
  )
}
