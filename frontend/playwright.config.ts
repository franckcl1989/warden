import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'on-first-retry',
  },
  // e2e 在 M2 门禁启用：先 npx playwright install chromium，再启动后端与 dev 服务
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
