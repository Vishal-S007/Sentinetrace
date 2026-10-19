import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'

import { api, ApiError, type ErrorPage, type IngestionErrorRow, type Job } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { JobStatusBadge } from '../components/JobStatusBadge'
import { Button, Empty, ErrorBanner, Loading, PageHeader } from '../components/ui'
import { formatBytes, formatCount, formatDateTime, formatDuration } from '../lib/format'
import { isActive, POLL_MS } from '../lib/jobs'

function msg(err: unknown) {
  return err instanceof ApiError ? err.message : 'Unexpected error'
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="bg-panel p-3">
      <dt className="text-xs uppercase tracking-wide text-ink-dim">{label}</dt>
      <dd className={`mt-1 text-lg tabular-nums ${tone ?? ''}`}>{value}</dd>
    </div>
  )
}

function ErrorsSection({ job }: { job: Job }) {
  const [page, setPage] = useState<ErrorPage | null>(null)
  const [rows, setRows] = useState<IngestionErrorRow[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const done = !isActive(job.status)

  useEffect(() => {
    if (!done) return
    let active = true
    api
      .jobErrors(job.id)
      .then((p) => {
        if (!active) return
        setPage(p)
        setRows(p.items)
      })
      .catch((err: unknown) => active && setError(msg(err)))
    return () => {
      active = false
    }
  }, [job.id, done, job.attempts])

  async function more() {
    if (!page?.next_after_id) return
    setBusy(true)
    try {
      const p = await api.jobErrors(job.id, page.next_after_id)
      setPage(p)
      setRows((prev) => [...prev, ...p.items])
    } catch (err) {
      setError(msg(err))
    } finally {
      setBusy(false)
    }
  }

  if (!done) return <p className="text-sm text-ink-dim">Rejected lines will be listed when processing finishes.</p>
  if (error) return <ErrorBanner message={`Could not load rejected lines: ${error}`} />
  if (!page) return <Loading label="Loading rejected lines…" />
  if (job.rejected_count === 0) return <Empty>No lines were rejected.</Empty>

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-sm">
        <p className="text-ink-dim">
          {formatCount(page.total_rejected)} rejected line{page.total_rejected === 1 ? '' : 's'}
          {page.truncated && ` · only the first ${formatCount(page.stored)} are stored`}
        </p>
        <a href={api.jobErrorsCsvUrl(job.id)} className="rounded-md border border-line bg-panel-2 px-3 py-1.5 hover:border-accent" download>
          Download CSV
        </a>
      </div>
      <div className="overflow-x-auto rounded-md border border-line" tabIndex={0} role="region" aria-label="Rejected lines table">
        <table className="w-full min-w-[700px] text-left text-sm">
          <thead className="bg-panel text-xs uppercase tracking-wide text-ink-dim">
            <tr>
              <th className="w-20 px-3 py-2">Line</th>
              <th className="w-64 px-3 py-2">Reason</th>
              <th className="px-3 py-2">Original content</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="border-t border-line align-top">
                <td className="px-3 py-2 font-mono text-xs tabular-nums">{r.line_number}</td>
                <td className="px-3 py-2 text-warn">{r.reason}</td>
                <td className="px-3 py-2">
                  {/* Untrusted log content: rendered as text only, never as HTML. */}
                  <code className="block max-h-24 overflow-auto whitespace-pre-wrap break-all font-mono text-xs text-ink-dim">{r.raw_line}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {page.next_after_id && (
        <div className="mt-3 text-right">
          <Button onClick={() => void more()} disabled={busy}>
            {busy ? 'Loading…' : 'Show more'}
          </Button>
        </div>
      )}
    </div>
  )
}

export function JobDetailPage() {
  const { id } = useParams()
  const jobId = Number(id)
  const { can } = useAuth()
  const [job, setJob] = useState<Job | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [retryError, setRetryError] = useState<string | null>(null)
  const [retrying, setRetrying] = useState(false)

  useEffect(() => {
    let active = true
    api
      .job(jobId)
      .then((j) => active && setJob(j))
      .catch((err: unknown) => active && setError(msg(err)))
    return () => {
      active = false
    }
  }, [jobId])

  const polling = job !== null && isActive(job.status)
  useEffect(() => {
    if (!polling) return
    const timer = setInterval(() => {
      api.job(jobId).then(setJob).catch(() => {})
    }, POLL_MS)
    return () => clearInterval(timer)
  }, [polling, jobId])

  async function retry() {
    setRetrying(true)
    setRetryError(null)
    try {
      setJob(await api.retryJob(jobId))
    } catch (err) {
      setRetryError(msg(err))
    } finally {
      setRetrying(false)
    }
  }

  if (!Number.isInteger(jobId) || jobId <= 0) return <ErrorBanner message="Invalid job id." />
  if (error) return <ErrorBanner message={`Could not load job #${jobId}: ${error}`} />
  if (!job) return <Loading label="Loading job…" />

  return (
    <section className="max-w-5xl">
      <p className="mb-2 text-sm">
        <Link to="/jobs" className="text-ink-dim hover:text-ink">
          ← All jobs
        </Link>
      </p>
      <PageHeader
        title={`Job #${job.id}`}
        subtitle={`${job.filename} → ${job.source_name}`}
        actions={
          <div className="flex items-center gap-3">
            <JobStatusBadge status={job.status} />
            {job.status === 'failed' && can('logs:import') && (
              <Button variant="primary" onClick={() => void retry()} disabled={retrying}>
                {retrying ? 'Retrying…' : 'Retry'}
              </Button>
            )}
          </div>
        }
      />
      {retryError && <div className="mb-4"><ErrorBanner message={retryError} /></div>}
      {job.error_message && (
        <div role="alert" className="mb-4 rounded-md border border-crit/40 bg-crit/10 p-3 text-sm">
          <p className="font-medium text-crit">Processing failed</p>
          <p className="mt-1 text-ink-dim">{job.error_message}</p>
        </div>
      )}
      {polling && (
        <p role="status" className="mb-4 text-sm text-accent">
          {job.status === 'queued' ? 'Waiting for a worker…' : `Processing… ${formatCount(job.total_lines)} lines read so far.`}
        </p>
      )}

      <dl className="mb-6 grid grid-cols-2 gap-px overflow-hidden rounded-md border border-line bg-line md:grid-cols-4">
        <Stat label="Lines read" value={formatCount(job.total_lines)} />
        <Stat label="Parsed events" value={formatCount(job.parsed_count)} tone="text-ok" />
        <Stat label="Rejected" value={formatCount(job.rejected_count)} tone={job.rejected_count ? 'text-warn' : ''} />
        <Stat label="Duplicates skipped" value={formatCount(job.duplicate_count)} />
      </dl>

      <dl className="mb-8 grid grid-cols-[10rem_1fr] gap-y-1.5 rounded-md border border-line bg-panel p-4 text-sm">
        <dt className="text-ink-dim">Format</dt>
        <dd>
          {job.format ?? '—'}
          {job.requested_format && <span className="text-ink-dim"> (chosen at upload)</span>}
        </dd>
        <dt className="text-ink-dim">File size / encoding</dt>
        <dd>
          {formatBytes(job.size_bytes)} · {job.encoding}
        </dd>
        <dt className="text-ink-dim">Uploaded</dt>
        <dd>
          {formatDateTime(job.created_at)}
          {job.created_by && ` by ${job.created_by}`}
        </dd>
        <dt className="text-ink-dim">Processing time</dt>
        <dd>{formatDuration(job.started_at, job.finished_at)}</dd>
        <dt className="text-ink-dim">Attempts</dt>
        <dd>{job.attempts}</dd>
      </dl>

      <h2 className="mb-3 text-sm font-semibold">Rejected lines</h2>
      <ErrorsSection job={job} />
    </section>
  )
}
