import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-sm9-forge/',
  test: {
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'e2e/**'],
  },
});
