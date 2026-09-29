import { defineConfig } from '@playwright/test';

/**
 * PORT 4646 IS THIS LAB'S OWN, AND THAT IS NOT A PREFERENCE.
 *
 * Vite's default preview port is 4173, and every lab in this fleet that keeps
 * the default collides with every other. The failure is not a refused bind —
 * `reuseExistingServer` sees SOMETHING answering on 4173 and hands the suites a
 * different lab's build, so the gates run green or red against a page this repo
 * did not produce. A cold run here returned 302 on `/` and 404 on
 * `/crypto-lab-sm9-forge/` because crypto-lab-glass-box owned the port.
 *
 * 4646 was chosen by scanning every sibling `playwright.config.ts` in the fleet
 * for a port already claimed. All three places below must name the same port:
 * `baseURL` is what the specs resolve `./` against, `webServer.command` is what
 * actually binds, and `webServer.url` is what Playwright polls before starting.
 */
const PORT = 4646;
const BASE = `http://localhost:${PORT}/crypto-lab-sm9-forge/`;

export default defineConfig({
  testDir: './e2e',
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: BASE,
    colorScheme: 'dark',
  },
  projects: [
    { name: 'claims', testMatch: /claims\.spec\.ts/ },
    { name: 'a11y', testMatch: /a11y\.spec\.ts/ },
    { name: 'geometry', testMatch: /geometry\.spec\.ts/ },
  ],
  webServer: {
    // build FIRST, so what the gate judges is what ships
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: BASE,
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
