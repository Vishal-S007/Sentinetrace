import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'

// Automated WCAG 2.1 A/AA checks (axe-core) on every screen, plus keyboard-only use.
// axe finds roughly a third to a half of accessibility issues; the keyboard test and
// manual review cover part of the rest.
const ADMIN_USER = process.env.E2E_ADMIN_USER ?? 'admin'
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? ''
const WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']

test.beforeAll(() => {
  if (!ADMIN_PASSWORD) throw new Error('Set E2E_ADMIN_PASSWORD (and E2E_ADMIN_USER) for the E2E run')
})

async function audit(page: Page, label: string): Promise<string[]> {
  const result = await new AxeBuilder({ page }).withTags(WCAG).analyze()
  return result.violations.map(
    (v) => `${label}: ${v.id} (${v.impact}) ${v.help} -> ${v.nodes.map((n) => n.target.join(' ')).slice(0, 3).join(' | ')}`,
  )
}

async function signIn(page: Page) {
  await page.goto('/login')
  await page.getByLabel('Username').fill(ADMIN_USER)
  await page.getByLabel('Password').fill(ADMIN_PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Security overview' })).toBeVisible()
}

test('public pages meet WCAG 2.1 AA (automated checks)', async ({ page }) => {
  const problems: string[] = []
  const pages: [string, string][] = [
    ['/login', 'SentinelTrace'],
    ['/legal/privacy', 'Privacy policy'],
    ['/legal/terms', 'Terms of service'],
    ['/legal/cookies', 'Cookie policy'],
  ]
  for (const [path, heading] of pages) {
    await page.goto(path)
    await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible()
    problems.push(...(await audit(page, path)))
  }
  expect(problems).toEqual([])
})

test('every signed-in screen meets WCAG 2.1 AA (automated checks)', async ({ page }) => {
  await signIn(page)
  await page.getByRole('button', { name: 'All time' }).click()
  await expect(page.getByRole('region', { name: 'Alerts by severity' })).toBeVisible()
  const problems = await audit(page, '/dashboard')

  const screens: [string, string][] = [
    ['/alerts', 'Alert queue'],
    ['/incidents', 'Incidents'],
    ['/incidents/new', 'New incident'],
    ['/events', 'Event explorer'],
    ['/rules', 'Detection rules'],
    ['/rules/ST-AUTH-002', 'Potential brute force or password spraying'],
    ['/sources', 'Log sources'],
    ['/jobs', 'Ingestion jobs'],
    ['/status', 'Settings & status'],
    ['/account', 'My account'],
    ['/admin/users', 'Users & roles'],
    ['/admin/audit', 'Audit log'],
    ['/admin/retention', 'Data retention'],
  ]
  for (const [path, heading] of screens) {
    await page.goto(path)
    await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible()
    problems.push(...(await audit(page, path)))
  }

  // Detail screens, when data exists.
  for (const [list, region] of [
    ['/alerts', 'Evidence'],
    ['/incidents', null],
    ['/jobs', null],
  ] as const) {
    await page.goto(list)
    const first = page.getByRole('table').getByRole('link').first()
    if (await first.count()) {
      await first.click()
      if (region) await expect(page.getByRole('region', { name: region })).toBeVisible()
      else await page.waitForLoadState('networkidle')
      problems.push(...(await audit(page, `${list}/:id`)))
    }
  }
  await page.goto('/events')
  const firstEvent = page.getByRole('button', { name: /^Open event/ }).first()
  if (await firstEvent.count()) {
    await firstEvent.click()
    problems.push(...(await audit(page, '/events (detail open)')))
  }
  expect(problems).toEqual([])
})

test('keyboard only: sign in, skip link and sidebar navigation', async ({ page }) => {
  await page.goto('/login')
  // The username field has focus on load; type and tab through the form.
  await page.keyboard.type(ADMIN_USER)
  await page.keyboard.press('Tab')
  await page.keyboard.type(ADMIN_PASSWORD)
  await page.keyboard.press('Enter')
  await expect(page.getByRole('heading', { name: 'Security overview' })).toBeVisible()

  // First Tab reaches the skip link, which moves focus to the main content.
  await page.keyboard.press('Tab')
  const skip = page.getByRole('link', { name: 'Skip to main content' })
  await expect(skip).toBeFocused()
  await expect(skip).toBeVisible()
  await page.keyboard.press('Enter')
  await expect(page.locator('main')).toBeFocused()

  // Reach "Alerts" in the sidebar with the keyboard and open it.
  await page.goto('/dashboard')
  let reached = false
  for (let i = 0; i < 10 && !reached; i++) {
    await page.keyboard.press('Tab')
    reached = await page.getByRole('link', { name: 'Alerts', exact: true }).evaluate((el) => el === document.activeElement)
  }
  expect(reached).toBe(true)
  await page.keyboard.press('Enter')
  await expect(page.getByRole('heading', { name: 'Alert queue' })).toBeVisible()

  // Focused controls show a visible focus ring.
  const outline = await page.getByRole('link', { name: 'Alerts', exact: true }).evaluate((el) => getComputedStyle(el).outlineStyle)
  expect(outline).not.toBe('none')
})
