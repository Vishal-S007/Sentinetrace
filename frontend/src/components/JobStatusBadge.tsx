import type { JobStatus } from '../api/client'

const STYLES: Record<JobStatus, { label: string; cls: string }> = {
  queued: { label: 'Queued', cls: 'border-line text-ink-dim' },
  running: { label: 'Running', cls: 'border-accent/50 text-accent' },
  completed: { label: 'Completed', cls: 'border-ok/50 text-ok' },
  completed_with_errors: { label: 'Completed with errors', cls: 'border-warn/50 text-warn' },
  failed: { label: 'Failed', cls: 'border-crit/50 text-crit' },
}

export function JobStatusBadge({ status }: { status: JobStatus }) {
  const s = STYLES[status]
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs ${s.cls}`}>
      {status === 'running' && <span aria-hidden className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />}
      {s.label}
    </span>
  )
}
