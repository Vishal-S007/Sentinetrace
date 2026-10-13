import { expect, test, type Page } from '@playwright/test'

// Needs the backend API *and* the ingestion worker running against the same database.
const ADMIN_USER = process.env.E2E_ADMIN_USER ?? 'admin'
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? ''

async function signIn(page: Page) {
  await page.goto('/login')
  await page.getByLabel('Username').fill(ADMIN_USER)
  await page.getByLabel('Password').fill(ADMIN_PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible()
}

function accessLog(runId: string): string {
  // Unique paths per run so re-running against the same database isn't a duplicate upload.
  return [
    `198.51.100.10 - - [10/Oct/2026:13:55:36 +0000] "GET /e2e/${runId}/a HTTP/1.1" 200 120 "-" "Mozilla/5.0"`,
    `198.51.100.11 - - [10/Oct/2026:13:55:37 +0000] "GET /e2e/${runId}/b HTTP/1.1" 404 0 "-" "Mozilla/5.0"`,
    `this line is not an access log entry ${runId}`,
    `198.51.100.12 - - [10/Oct/2026:13:55:38 +0530] "POST /e2e/${runId}/login HTTP/1.1" 401 0 "-" "curl/8.5.0"`,
    '',
  ].join('\n')
}

test.beforeAll(() => {
  if (!ADMIN_PASSWORD) throw new Error('Set E2E_ADMIN_PASSWORD (and E2E_ADMIN_USER) for the E2E run')
})

test('import a log file: create source, upload, process, inspect results and rejected lines', async ({ page }) => {
  const runId = Date.now().toString(36)
  const sourceName = `e2e-web-${runId}`
  await signIn(page)

  // Create a source.
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Log sources' }).click()
  const create = page.getByRole('form', { name: 'Add log source' })
  await create.getByLabel('Name').fill(sourceName)
  await create.getByLabel('Format').selectOption('apache_combined')
  await create.getByRole('button', { name: 'Create source' }).click()
  await expect(page.getByText(sourceName, { exact: true })).toBeVisible()

  // Upload a file to it.
  const uploadForm = page.getByRole('form', { name: `Upload to ${sourceName}` })
  await uploadForm.getByLabel(`Log file for ${sourceName}`).setInputFiles({
    name: `access-${runId}.log`,
    mimeType: 'text/plain',
    buffer: Buffer.from(accessLog(runId)),
  })
  await uploadForm.getByRole('button', { name: 'Upload' }).click()
  const jobLink = uploadForm.getByRole('link', { name: /job #\d+/ })
  await expect(jobLink).toBeVisible()

  // The worker processes it; the detail page polls until it finishes.
  await jobLink.click()
  await expect(page.getByText('Completed with errors')).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText('Parsed events').locator('xpath=following-sibling::dd')).toHaveText('3')
  await expect(page.getByText('Rejected', { exact: true }).locator('xpath=following-sibling::dd')).toHaveText('1')

  // The rejected line is listed with its line number and original content.
  const row = page.getByRole('row').filter({ hasText: `this line is not an access log entry ${runId}` })
  await expect(row).toBeVisible()
  await expect(row.getByRole('cell').first()).toHaveText('3')

  // The CSV export contains the same rejected line.
  const csvHref = await page.getByRole('link', { name: 'Download CSV' }).getAttribute('href')
  const csv = await page.evaluate(async (href) => (await fetch(href!)).text(), csvHref)
  expect(csv).toContain('line_number,reason,raw_line')
  expect(csv).toContain(`this line is not an access log entry ${runId}`)

  // Uploading the identical file again is refused as a duplicate.
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Log sources' }).click()
  const again = page.getByRole('form', { name: `Upload to ${sourceName}` })
  await again.getByLabel(`Log file for ${sourceName}`).setInputFiles({
    name: 'renamed.log',
    mimeType: 'text/plain',
    buffer: Buffer.from(accessLog(runId)),
  })
  await again.getByRole('button', { name: 'Upload' }).click()
  await expect(again.getByRole('alert')).toContainText('already imported')

  // The jobs list shows the job with its counts.
  await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Ingestion jobs' }).click()
  const jobRow = page.getByRole('row').filter({ hasText: `access-${runId}.log` })
  await expect(jobRow.getByText('Completed with errors')).toBeVisible()
})
