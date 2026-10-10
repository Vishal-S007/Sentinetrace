import { expect, test } from '@playwright/test'

test('status page shows live API and database health from the real backend', async ({ page }) => {
  await page.goto('/')
  await expect(page).toHaveURL(/\/status$/)
  await expect(page.getByRole('heading', { name: 'System status' })).toBeVisible()
  await expect(page.getByText('Online')).toBeVisible()
  await expect(page.getByText('Connected')).toBeVisible()

  await page.getByRole('button', { name: /re-check/i }).click()
  await expect(page.getByText('Connected')).toBeVisible()
})

test('unknown route shows not-found message', async ({ page }) => {
  await page.goto('/no-such-page')
  await expect(page.getByText('Page not found.')).toBeVisible()
})
