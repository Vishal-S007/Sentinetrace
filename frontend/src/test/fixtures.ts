import type { Job, LogFormat, LogSource } from '../api/client'

export const formats: LogFormat[] = [
  { id: 'apache_combined', label: 'Apache combined', example: '1.2.3.4 - - [..] "GET / HTTP/1.1" 200 1 "-" "UA"', detectable: true },
  { id: 'nginx_custom', label: 'Nginx custom log_format', example: 'pattern', detectable: false },
  { id: 'json', label: 'JSON lines', example: '{"timestamp":"..."}', detectable: true },
]

export function makeSource(over: Partial<LogSource> = {}): LogSource {
  return {
    id: 1,
    name: 'web-prod',
    description: 'Production nginx',
    format: 'apache_combined',
    custom_pattern: null,
    timezone: 'UTC',
    enabled: true,
    created_at: '2026-10-10T00:00:00Z',
    file_count: 2,
    event_count: 1234,
    last_upload_at: '2026-10-11T00:00:00Z',
    ...over,
  }
}

export function makeJob(over: Partial<Job> = {}): Job {
  return {
    id: 7,
    status: 'completed',
    source_id: 1,
    source_name: 'web-prod',
    file_id: 3,
    filename: 'access.log',
    size_bytes: 2048,
    encoding: 'utf-8',
    requested_format: null,
    format: 'apache_combined',
    total_lines: 10,
    parsed_count: 8,
    rejected_count: 2,
    duplicate_count: 0,
    errors_truncated: false,
    error_message: null,
    attempts: 1,
    created_by: 'analyst1',
    created_at: '2026-10-12T10:00:00Z',
    started_at: '2026-10-12T10:00:01Z',
    finished_at: '2026-10-12T10:00:02Z',
    ...over,
  }
}
