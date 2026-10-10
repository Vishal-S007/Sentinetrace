/** Minimal typed API client. All calls are same-origin and send cookies. */

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

export interface HealthResponse {
  status: string
  version: string
}

export interface ReadinessResponse {
  status: 'ready' | 'not_ready'
  database: 'ok' | 'unavailable'
}

async function request<T>(path: string, init?: RequestInit, acceptStatuses: number[] = []): Promise<T> {
  let resp: Response
  try {
    resp = await fetch(path, { credentials: 'same-origin', ...init })
  } catch {
    throw new ApiError(0, 'Cannot reach the SentinelTrace API')
  }
  if (!resp.ok && !acceptStatuses.includes(resp.status)) {
    let message = `Request failed (${resp.status})`
    try {
      const body = (await resp.json()) as { detail?: unknown }
      if (typeof body.detail === 'string') message = body.detail
    } catch {
      /* non-JSON error body: keep the generic message */
    }
    throw new ApiError(resp.status, message)
  }
  return (await resp.json()) as T
}

export const api = {
  health: () => request<HealthResponse>('/api/health'),
  // 503 is a meaningful readiness answer, not a transport failure.
  ready: () => request<ReadinessResponse>('/api/ready', undefined, [503]),
}
