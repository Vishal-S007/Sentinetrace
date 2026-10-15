/// <reference types="vitest/config" />
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

const apiTarget = process.env.ST_API_URL ?? 'http://127.0.0.1:8000'

// Same policy nginx sends in production (frontend/nginx.conf), so the E2E run (against
// `vite preview`) fails if the app ever needs inline scripts or third-party resources.
const CSP =
  "default-src 'self'; img-src 'self' data:; style-src 'self'; connect-src 'self'; " +
  "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    // Same-origin in development: the browser talks to Vite, Vite proxies /api.
    proxy: { '/api': { target: apiTarget, changeOrigin: false } },
  },
  preview: {
    port: 4173,
    headers: { 'Content-Security-Policy': CSP, 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY' },
    proxy: { '/api': { target: apiTarget, changeOrigin: false } },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: false,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.test.tsx', 'src/test/**', 'src/main.tsx'],
      reporter: ['text-summary', 'text'],
      // A little below the measured level, so a real drop fails the build.
      thresholds: { lines: 82, statements: 80, functions: 78, branches: 70 },
    },
  },
})
