import { useState, type FormEvent } from 'react'
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom'

import { ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { Button, ErrorBanner, Field, TextInput } from '../components/ui'

interface LocationState {
  from?: string
  reason?: 'expired' | 'logged_out'
}

export function LoginPage() {
  const { state, login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as LocationState | null)?.from ?? '/'
  const reason = (location.state as LocationState | null)?.reason

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  if (state.status === 'authenticated') return <Navigate to={from} replace />

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await login(username, password)
      navigate(from === '/login' ? '/' : from, { replace: true })
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setError('Too many failed attempts. Please wait a few minutes and try again.')
      } else if (err instanceof ApiError && err.status === 401) {
        setError('Invalid username or password.')
      } else {
        setError(err instanceof ApiError ? err.message : 'Login failed.')
      }
      setPassword('')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex min-h-full flex-col items-center justify-center gap-4 p-4">
      <form onSubmit={onSubmit} className="w-full max-w-sm space-y-4 rounded-lg border border-line bg-panel p-6" noValidate>
        <div className="flex items-center gap-2">
          <span aria-hidden className="h-2.5 w-2.5 rounded-full bg-accent" />
          <h1 className="text-lg font-semibold tracking-tight">SentinelTrace</h1>
        </div>
        <p className="text-sm text-ink-dim">Sign in to continue.</p>

        {reason === 'expired' && !error && (
          <p role="status" className="rounded-md border border-warn/40 bg-warn/10 p-3 text-sm text-warn">
            Your session has ended. Please sign in again.
          </p>
        )}
        {error && <ErrorBanner message={error} />}

        <Field label="Username">
          <TextInput
            name="username"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            autoFocus
          />
        </Field>
        <Field label="Password">
          <TextInput
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </Field>
        <Button type="submit" variant="primary" className="w-full py-2" disabled={submitting || !username || !password}>
          {submitting ? 'Signing in…' : 'Sign in'}
        </Button>
      </form>
      <footer className="w-full max-w-sm space-y-2 text-xs text-ink-dim">
        <p role="note">
          SentinelTrace uses two strictly necessary cookies to keep you signed in and to block forged requests. There are
          no tracking or advertising cookies, so there is nothing to accept.{' '}
          <Link to="/legal/cookies" className="text-accent underline underline-offset-2">
            Cookie policy
          </Link>
        </p>
        <p>
          By signing in you agree to the{' '}
          <Link to="/legal/terms" className="text-accent underline underline-offset-2">
            terms of service
          </Link>
          . Your data is handled as described in the{' '}
          <Link to="/legal/privacy" className="text-accent underline underline-offset-2">
            privacy policy
          </Link>
          .
        </p>
      </footer>
    </div>
  )
}
