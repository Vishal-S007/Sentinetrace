import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import { formats, makeJob, makeSource } from '../test/fixtures'
import { json, makeMe, mockApi, renderWithAuth, setCsrfCookie } from '../test/utils'
import { SourcesPage } from './SourcesPage'

function base(role: 'analyst' | 'viewer' = 'analyst', extra: Parameters<typeof mockApi>[0] = {}) {
  return mockApi({
    'GET /api/auth/me': () => json(200, makeMe(role)),
    'GET /api/sources': () => json(200, [makeSource()]),
    'GET /api/formats': () => json(200, formats),
    ...extra,
  })
}

describe('SourcesPage', () => {
  it('lists sources with stats', async () => {
    base()
    renderWithAuth(<SourcesPage />)
    const card = (await screen.findByText('web-prod')).closest('li')!
    expect(within(card).getByText('Format').nextSibling).toHaveTextContent('Apache combined')
    expect(within(card).getByText('1,234')).toBeInTheDocument()
  })

  it('shows loading then error states', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/sources': () => json(500, { detail: 'Internal server error' }),
      'GET /api/formats': () => json(200, formats),
    })
    renderWithAuth(<SourcesPage />)
    expect(screen.getByRole('status')).toHaveTextContent('Loading log sources')
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load log sources')
  })

  it('shows the empty state', async () => {
    mockApi({
      'GET /api/auth/me': () => json(200, makeMe('analyst')),
      'GET /api/sources': () => json(200, []),
      'GET /api/formats': () => json(200, formats),
    })
    renderWithAuth(<SourcesPage />)
    expect(await screen.findByText(/No log sources yet/)).toBeInTheDocument()
  })

  it('creates an nginx_custom source with its log_format', async () => {
    setCsrfCookie('tok')
    const created = makeSource({ id: 2, name: 'edge', format: 'nginx_custom', custom_pattern: '$remote_addr [$time_local]' })
    const { calls } = base('analyst', { 'POST /api/sources': () => json(201, created) })
    renderWithAuth(<SourcesPage />)
    const form = await screen.findByRole('form', { name: 'Add log source' })
    expect(within(form).queryByLabelText(/Nginx log_format/)).not.toBeInTheDocument()
    await userEvent.type(within(form).getByLabelText('Name'), 'edge')
    await userEvent.selectOptions(within(form).getByLabelText('Format'), 'nginx_custom')
    const create = within(form).getByRole('button', { name: 'Create source' })
    expect(create).toBeDisabled() // pattern required
    await userEvent.click(within(form).getByLabelText(/Nginx log_format/))
    await userEvent.paste('$remote_addr [$time_local]')
    await userEvent.click(create)
    expect(await screen.findByText('edge')).toBeInTheDocument()
    const post = calls.find((c) => c.method === 'POST')!
    expect(post.body).toMatchObject({ name: 'edge', format: 'nginx_custom', custom_pattern: '$remote_addr [$time_local]', timezone: 'UTC' })
    expect(post.headers['X-CSRF-Token']).toBe('tok')
  })

  it('shows server validation errors when creating a source', async () => {
    base('analyst', { 'POST /api/sources': () => json(409, { detail: 'A source with this name already exists' }) })
    renderWithAuth(<SourcesPage />)
    const form = await screen.findByRole('form', { name: 'Add log source' })
    await userEvent.type(within(form).getByLabelText('Name'), 'web-prod')
    await userEvent.click(within(form).getByRole('button', { name: 'Create source' }))
    expect(await within(form).findByRole('alert')).toHaveTextContent('already exists')
  })

  it('uploads a file as multipart with CSRF and links to the job', async () => {
    setCsrfCookie('tok')
    const { calls } = base('analyst', {
      'POST /api/sources/1/files': () => json(201, { file: {}, job: makeJob({ id: 42, status: 'queued' }) }),
    })
    renderWithAuth(<SourcesPage />)
    const form = await screen.findByRole('form', { name: 'Upload to web-prod' })
    const file = new File(['log line\n'], 'access.log', { type: 'text/plain' })
    await userEvent.upload(within(form).getByLabelText(/Log file for web-prod/), file)
    await userEvent.selectOptions(within(form).getByLabelText('Format override for web-prod'), 'json')
    await userEvent.click(within(form).getByRole('button', { name: 'Upload' }))

    const link = await within(form).findByRole('link', { name: 'job #42' })
    expect(link).toHaveAttribute('href', '/jobs/42')
    const post = calls.find((c) => c.url === '/api/sources/1/files')!
    expect(post.headers['X-CSRF-Token']).toBe('tok')
    expect(post.headers['Content-Type']).toBeUndefined() // browser sets multipart boundary
    const form_data = post.body as FormData
    expect((form_data.get('file') as File).name).toBe('access.log')
    expect(form_data.get('format')).toBe('json')
  })

  it('shows upload rejections (duplicate file)', async () => {
    base('analyst', {
      'POST /api/sources/1/files': () => json(409, { detail: 'This exact file was already imported into this source' }),
    })
    renderWithAuth(<SourcesPage />)
    const form = await screen.findByRole('form', { name: 'Upload to web-prod' })
    await userEvent.upload(within(form).getByLabelText(/Log file for web-prod/), new File(['x'], 'a.log'))
    await userEvent.click(within(form).getByRole('button', { name: 'Upload' }))
    expect(await within(form).findByRole('alert')).toHaveTextContent('already imported')
  })

  it('disables a source', async () => {
    base('analyst', { 'PATCH /api/sources/1': (c) => json(200, makeSource(c.body as object)) })
    renderWithAuth(<SourcesPage />)
    const card = (await screen.findByText('web-prod')).closest('li')!
    await userEvent.click(within(card).getByRole('button', { name: 'Disable' }))
    expect(await within(card).findByText('Disabled')).toBeInTheDocument()
    expect(within(card).getByRole('button', { name: 'Upload' })).toBeDisabled()
  })

  it('viewers see sources but no create or upload controls', async () => {
    base('viewer')
    renderWithAuth(<SourcesPage />)
    await screen.findByText('web-prod')
    expect(screen.queryByRole('form', { name: 'Add log source' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Upload' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Disable' })).not.toBeInTheDocument()
  })
})
