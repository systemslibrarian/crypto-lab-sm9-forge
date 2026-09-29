import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4173/crypto-lab-sm9-forge/',
    colorScheme: 'dark',
  },
  projects: [
    { name: 'claims', testMatch: /claims\.spec\.ts/ },
    { name: 'a11y', testMatch: /a11y\.spec\.ts/ },
  ],
  webServer: {
    // build FIRST, so what the gate judges is what ships
    command: 'npm run build && npm run preview -- --port 4173 --strictPort',
    url: 'http://localhost:4173/crypto-lab-sm9-forge/',
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
