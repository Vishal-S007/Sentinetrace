import { expect, test, type Page } from '@playwright/test'

// Runs against a real backend + database. CI seeds this admin with the CLI.
const ADMIN_USER = process.env.E2E_ADMIN_USER ?? 'admin'
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? ''

async function signIn(page: Page, username: string, password: string) {
  await page.goto('/login')
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
}

test.beforeAll(() => {
  if (!ADMIN_PASSWORD) throw new Error('Set E2E_ADMIN_PASSWORD (and E2E_ADMIN_USER) for the E2E run')
})

test('anonymous users are sent to the login page', async ({ page }) => {
  await page.goto('/status')
  await expect(page).toHaveURL(/\/login$/)
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible()
})

test('wrong password shows a generic error', async ({ page }) => {
  await signIn(page, ADMIN_USER, 'definitely-not-the-password')
  await expect(page.getByRole('alert')).toHaveText('Invalid username or password.')
  await expect(page).toHaveURL(/\/login$/)
})

test('admin manages users, sees the audit trail, and RBAC applies to the new user', async ({ page, browser }) => {
  const suffix = Date.now().toString(36)
  const viewerName = `e2e.viewer.${suffix}`
  const viewerPassword = `viewer-password-${suffix}`

  // Admin signs in and sees live system status.
  await signIn(page, ADMIN_USER, ADMIN_PASSWORD)
  await expect(page.getByRole('heading', { name: 'System status' })).toBeVisible()
  await expect(page.getByText('Online')).toBeVisible()
  await expect(page.getByText('Connected')).toBeVisible()

  // Create a viewer.
  await page.getByRole('link', { name: 'Users & roles' }).click()
  const form = page.getByRole('form', { name: 'Create user' })
  await form.getByLabel(/Username/).fill(viewerName)
  await form.getByLabel(/Initial password/).fill(viewerPassword)
  await form.getByLabel('Role').selectOption('viewer')
  await form.getByRole('button', { name: 'Create user' }).click()
  await expect(page.getByText(`User ${viewerName} created.`)).toBeVisible()
  await expect(page.getByRole('cell', { name: viewerName })).toBeVisible()

  // The creation is in the audit log.
  await page.getByRole('link', { name: 'Audit log' }).click()
  await page.getByLabel('Action').fill('user.create')
  await page.getByRole('button', { name: 'Apply' }).click()
  await expect(page.getByText(viewerName).first()).toBeVisible()

  // The viewer, in a separate browser context, has no admin access.
  const viewerContext = await browser.newContext()
  const viewer = await viewerContext.newPage()
  await signIn(viewer, viewerName, viewerPassword)
  await expect(viewer.getByRole('heading', { name: 'System status' })).toBeVisible()
  const nav = viewer.getByRole('navigation', { name: 'Main' })
  await expect(nav.getByRole('link', { name: 'Users & roles' })).toHaveCount(0)
  await viewer.goto('/admin/users')
  await expect(viewer.getByText('Access denied')).toBeVisible()
  // The server enforces it too, not just the UI.
  const apiStatus = await viewer.evaluate(async () => (await fetch('/api/users')).status)
  expect(apiStatus).toBe(403)

  // Admin disables the viewer; the viewer's session ends immediately.
  await page.getByRole('link', { name: 'Users & roles' }).click()
  const row = page.getByRole('row').filter({ hasText: viewerName })
  await row.getByRole('button', { name: 'Disable' }).click()
  await expect(row.getByText('Disabled')).toBeVisible()
  await viewer.goto('/status')
  await expect(viewer).toHaveURL(/\/login$/)
  await viewerContext.close()

  // Sign out: the old session no longer works.
  await page.getByRole('button', { name: 'Sign out' }).first().click()
  await expect(page).toHaveURL(/\/login$/)
  await page.goto('/admin/users')
  await expect(page).toHaveURL(/\/login$/)
  const meStatus = await page.evaluate(async () => (await fetch('/api/auth/me')).status)
  expect(meStatus).toBe(401)
})
