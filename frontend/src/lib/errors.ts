import { ApiError } from '../api/client'

export function errorMessage(err: unknown): string {
  return err instanceof ApiError ? err.message : 'Unexpected error'
}
