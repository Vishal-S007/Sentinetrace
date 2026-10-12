import { useCallback, useEffect, useState, type FormEvent } from 'react'

import { api, ApiError, type AuditEntry } from '../api/client'
import { formatDateTime } from '../lib/format'
import { Button, Empty, ErrorBanner, Field, Loading, PageHeader, TextInput } from '../components/ui'

const PAGE_SIZE = 50

interface Filters {
  action: string
  actor: string
}

export function AuditPage() {
  const [filters, setFilters] = useState<Filters>({ action: '', actor: '' })
  const [draft, setDraft] = useState<Filters>(filters)
  const [items, setItems] = useState<AuditEntry[]>([])
  const [nextBefore, setNextBefore] = useState<number | null>(null)
  const [status, setStatus] = useState<'loading' | 'loaded' | 'error'>('loading')
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fetchPage = useCallback(
    (before?: number) => api.audit({ action: filters.action, actor: filters.actor, before_id: before, limit: PAGE_SIZE }),
    [filters],
  )

  useEffect(() => {
    let active = true
    fetchPage()
      .then((page) => {
        if (!active) return
        setItems(page.items)
        setNextBefore(page.next_before_id)
        setStatus('loaded')
      })
      .catch((err: unknown) => {
        if (!active) return
        setError(err instanceof ApiError ? err.message : 'Unexpected error')
        setStatus('error')
      })
    return () => {
      active = false
    }
  }, [fetchPage])

  async function loadMore() {
    if (nextBefore === null) return
    setLoadingMore(true)
    try {
      const page = await fetchPage(nextBefore)
      setItems((prev) => [...prev, ...page.items])
      setNextBefore(page.next_before_id)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unexpected error')
    } finally {
      setLoadingMore(false)
    }
  }

  function applyFilters(e: FormEvent) {
    e.preventDefault()
    setStatus('loading')
    setError(null)
    setFilters({ action: draft.action.trim(), actor: draft.actor.trim() })
  }

  return (
    <section>
      <PageHeader title="Audit log" subtitle="Append-only record of security-relevant actions. Entries cannot be edited or deleted." />

      <form onSubmit={applyFilters} aria-label="Filter audit log" className="mb-4 flex flex-wrap items-end gap-3">
        <div className="w-56">
          <Field label="Action">
            <TextInput placeholder="e.g. auth.login.failure" value={draft.action} onChange={(e) => setDraft({ ...draft, action: e.target.value })} />
          </Field>
        </div>
        <div className="w-48">
          <Field label="Actor">
            <TextInput placeholder="username" value={draft.actor} onChange={(e) => setDraft({ ...draft, actor: e.target.value })} />
          </Field>
        </div>
        <Button type="submit">Apply</Button>
      </form>

      {status === 'loading' && <Loading label="Loading audit entries…" />}
      {status === 'error' && <ErrorBanner message={`Could not load the audit log: ${error}`} />}
      {status === 'loaded' && items.length === 0 && <Empty>No audit entries match these filters.</Empty>}
      {status === 'loaded' && items.length > 0 && (
        <>
          <div className="overflow-x-auto rounded-md border border-line">
            <table className="w-full min-w-[800px] text-left text-sm">
              <thead className="bg-panel text-xs uppercase tracking-wide text-ink-dim">
                <tr>
                  <th className="px-3 py-2">Time</th>
                  <th className="px-3 py-2">Action</th>
                  <th className="px-3 py-2">Actor</th>
                  <th className="px-3 py-2">Target</th>
                  <th className="px-3 py-2">IP</th>
                  <th className="px-3 py-2">Details</th>
                </tr>
              </thead>
              <tbody>
                {items.map((e) => (
                  <tr key={e.id} className="border-t border-line align-top">
                    <td className="whitespace-nowrap px-3 py-2 text-ink-dim">{formatDateTime(e.occurred_at)}</td>
                    <td className="px-3 py-2 font-mono text-xs">{e.action}</td>
                    <td className="px-3 py-2">{e.actor_username ?? '—'}</td>
                    <td className="whitespace-nowrap px-3 py-2 text-ink-dim">{e.target_type ? `${e.target_type} #${e.target_id}` : '—'}</td>
                    <td className="px-3 py-2 font-mono text-xs text-ink-dim">{e.ip ?? '—'}</td>
                    <td className="max-w-xs break-words px-3 py-2 font-mono text-xs text-ink-dim">
                      {Object.keys(e.details).length ? JSON.stringify(e.details) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {error && <div className="mt-3"><ErrorBanner message={error} /></div>}
          <div className="mt-3 flex items-center justify-between text-sm text-ink-dim">
            <span>Showing {items.length} entries</span>
            {nextBefore !== null && (
              <Button onClick={() => void loadMore()} disabled={loadingMore}>
                {loadingMore ? 'Loading…' : 'Load older entries'}
              </Button>
            )}
          </div>
        </>
      )}
    </section>
  )
}
