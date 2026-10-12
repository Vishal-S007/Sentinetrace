import { useCallback, useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'

import { api, ApiError, type Job, type JobStatus } from '../api/client'
import { JobStatusBadge } from '../components/JobStatusBadge'
import { Button, Empty, ErrorBanner, Loading, PageHeader, Select } from '../components/ui'
import { formatBytes, formatCount, formatDateTime } from '../lib/format'
import { isActive, POLL_MS } from '../lib/jobs'

const STATUSES: { value: '' | JobStatus; label: string }[] = [
  { value: '', label: 'All statuses' },
  { value: 'queued', label: 'Queued' },
  { value: 'running', label: 'Running' },
  { value: 'completed', label: 'Completed' },
  { value: 'completed_with_errors', label: 'Completed with errors' },
  { value: 'failed', label: 'Failed' },
]
const PAGE = 25

export function JobsPage() {
  const [params, setParams] = useSearchParams()
  const status = (params.get('status') ?? '') as '' | JobStatus
  const sourceId = Number(params.get('source_id')) || undefined

  const [items, setItems] = useState<Job[]>([])
  const [nextBefore, setNextBefore] = useState<number | null>(null)
  const [phase, setPhase] = useState<'loading' | 'loaded' | 'error'>('loading')
  const [error, setError] = useState<string | null>(null)
  const [loadingMore, setLoadingMore] = useState(false)

  const fetchFirst = useCallback(
    () => api.jobs({ status: status || undefined, source_id: sourceId, limit: PAGE }),
    [status, sourceId],
  )

  // Initial load and whenever filters change.
  useEffect(() => {
    let active = true
    fetchFirst()
      .then((page) => {
        if (!active) return
        setItems(page.items)
        setNextBefore(page.next_before_id)
        setPhase('loaded')
        setError(null)
      })
      .catch((err: unknown) => {
        if (!active) return
        setError(err instanceof ApiError ? err.message : 'Unexpected error')
        setPhase('error')
      })
    return () => {
      active = false
    }
  }, [fetchFirst])

  // While anything on screen is queued/running, refresh the first page periodically.
  const hasActive = items.some((j) => isActive(j.status))
  useEffect(() => {
    if (!hasActive) return
    const timer = setInterval(() => {
      fetchFirst()
        .then((page) => {
          setItems((prev) => {
            const fresh = new Map(page.items.map((j) => [j.id, j]))
            const older = prev.filter((j) => !fresh.has(j.id) && j.id < (page.items.at(-1)?.id ?? Infinity))
            return [...page.items, ...older]
          })
        })
        .catch(() => {
          /* transient polling errors are ignored; the next tick retries */
        })
    }, POLL_MS)
    return () => clearInterval(timer)
  }, [hasActive, fetchFirst])

  async function loadMore() {
    if (nextBefore === null) return
    setLoadingMore(true)
    try {
      const page = await api.jobs({ status: status || undefined, source_id: sourceId, before_id: nextBefore, limit: PAGE })
      setItems((prev) => [...prev, ...page.items])
      setNextBefore(page.next_before_id)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unexpected error')
    } finally {
      setLoadingMore(false)
    }
  }

  function setFilter(key: string, value: string) {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setPhase('loading')
    setParams(next)
  }

  return (
    <section>
      <PageHeader
        title="Ingestion jobs"
        subtitle="Processing status and results for every imported file."
        actions={
          <Link to="/sources" className="rounded-md border border-line bg-panel-2 px-3 py-1.5 text-sm hover:border-accent">
            Upload a file
          </Link>
        }
      />
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="w-56">
          <Select aria-label="Filter by status" value={status} onChange={(e) => setFilter('status', e.target.value)}>
            {STATUSES.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </Select>
        </div>
        {sourceId && (
          <button type="button" className="text-sm text-ink-dim hover:text-ink" onClick={() => setFilter('source_id', '')}>
            Showing one source · clear
          </button>
        )}
        {hasActive && <span className="text-xs text-ink-dim">Auto-refreshing while jobs are processing…</span>}
      </div>

      {phase === 'loading' && <Loading label="Loading jobs…" />}
      {phase === 'error' && <ErrorBanner message={`Could not load jobs: ${error}`} />}
      {phase === 'loaded' && items.length === 0 && (
        <Empty>
          No jobs match. <Link className="underline" to="/sources">Upload a log file</Link> to create one.
        </Empty>
      )}
      {phase === 'loaded' && items.length > 0 && (
        <>
          <div className="overflow-x-auto rounded-md border border-line">
            <table className="w-full min-w-[900px] text-left text-sm">
              <thead className="bg-panel text-xs uppercase tracking-wide text-ink-dim">
                <tr>
                  <th className="px-3 py-2">Job</th>
                  <th className="px-3 py-2">File</th>
                  <th className="px-3 py-2">Source</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2 text-right">Parsed</th>
                  <th className="px-3 py-2 text-right">Rejected</th>
                  <th className="px-3 py-2 text-right">Duplicates</th>
                  <th className="px-3 py-2">Uploaded</th>
                </tr>
              </thead>
              <tbody>
                {items.map((j) => (
                  <tr key={j.id} className="border-t border-line">
                    <td className="px-3 py-2">
                      <Link className="font-mono text-accent hover:underline" to={`/jobs/${j.id}`}>
                        #{j.id}
                      </Link>
                    </td>
                    <td className="max-w-[16rem] truncate px-3 py-2" title={j.filename}>
                      {j.filename} <span className="text-xs text-ink-dim">({formatBytes(j.size_bytes)})</span>
                    </td>
                    <td className="px-3 py-2 text-ink-dim">{j.source_name}</td>
                    <td className="px-3 py-2">
                      <JobStatusBadge status={j.status} />
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums">{formatCount(j.parsed_count)}</td>
                    <td className={`px-3 py-2 text-right tabular-nums ${j.rejected_count ? 'text-warn' : ''}`}>{formatCount(j.rejected_count)}</td>
                    <td className="px-3 py-2 text-right tabular-nums text-ink-dim">{formatCount(j.duplicate_count)}</td>
                    <td className="whitespace-nowrap px-3 py-2 text-ink-dim">
                      {formatDateTime(j.created_at)}
                      {j.created_by && <span className="block text-xs">by {j.created_by}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {error && <div className="mt-3"><ErrorBanner message={error} /></div>}
          {nextBefore !== null && (
            <div className="mt-3 text-right">
              <Button onClick={() => void loadMore()} disabled={loadingMore}>
                {loadingMore ? 'Loading…' : 'Load older jobs'}
              </Button>
            </div>
          )}
        </>
      )}
    </section>
  )
}
