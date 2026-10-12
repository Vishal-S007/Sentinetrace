import type { JobStatus } from '../api/client'

export const ACTIVE_STATUSES: readonly JobStatus[] = ['queued', 'running']

export function isActive(status: JobStatus): boolean {
  return ACTIVE_STATUSES.includes(status)
}

/** How often pages poll while a job is still queued or running. */
export const POLL_MS = 2000
