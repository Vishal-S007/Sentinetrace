import { expect, test, type Page } from '@playwright/test'

// Runs every main screen under the production Content-Security-Policy (vite preview sends
// the same header as nginx) and fails on any CSP violation or uncaught page error.
const ADMIN_USER = process.env.E2E_ADMIN_USER ?? 'admin'
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? ''

test.beforeAll(() => {
  if (!ADMIN_PASSWORD) throw new Error('Set E2E_ADMIN_PASSWORD (and E2E_ADMIN_USER) for the E2E run')
})

function watch(page: Page): string[] {
  const problems: string[] = []
  page.on('console', (msg) => {
    if (msg.type() === 'error' && /Content Security Policy|Refused to/i.test(msg.text())) problems.push(msg.text())
  })
  page.on('pageerror', (err) => problems.push(`page error: ${err.message}`))
  return problems
}

test('every screen works under the production CSP', async ({ page }) => {
  const problems = watch(page)
  const resp = await page.goto('/login')
  const csp = resp!.headers()['content-security-policy']
  expect(csp).toContain("default-src 'self'")
  expect(csp).toContain("frame-ancestors 'none'")
  expect(csp).not.toContain('unsafe-eval')
  expect(csp).not.toContain('unsafe-inline')

  await page.getByLabel('Username').fill(ADMIN_USER)
  await page.getByLabel('Password').fill(ADMIN_PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Security overview' })).toBeVisible()
  await page.getByRole('button', { name: 'All time' }).click()
  await expect(page.getByRole('region', { name: 'Alerts by severity' })).toBeVisible()

  const screens: [string, string][] = [
    ['/alerts', 'Alert queue'],
    ['/incidents', 'Incidents'],
    ['/events', 'Event explorer'],
    ['/rules', 'Detection rules'],
    ['/sources', 'Log sources'],
    ['/jobs', 'Ingestion jobs'],
    ['/status', 'Settings & status'],
    ['/admin/users', 'Users & roles'],
    ['/admin/audit', 'Audit log'],
    ['/admin/retention', 'Data retention'],
  ]
  for (const [path, heading] of screens) {
    await page.goto(path)
    await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible()
  }
  // Open the first alert and rule, if any exist, to cover the detail screens too.
  await page.goto('/alerts')
  const firstAlert = page.getByRole('table').getByRole('link').first()
  if (await firstAlert.count()) {
    await firstAlert.click()
    await expect(page.getByRole('region', { name: 'Evidence' })).toBeVisible()
  }
  await page.goto('/rules/ST-AUTH-001')
  await expect(page.getByRole('form', { name: 'Rule settings' })).toBeVisible()

  expect(problems).toEqual([])
})

test('API responses carry a deny-all CSP', async ({ request }) => {
  const resp = await request.get('/api/health')
  expect(resp.headers()['content-security-policy']).toContain("default-src 'none'")
})
