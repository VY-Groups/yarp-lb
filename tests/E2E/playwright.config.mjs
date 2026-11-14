import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: '**/*.spec.mjs',
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  reporter: [['list']],
  workers: 1,
  timeout: 90000,
  expect: { timeout: 10000 },
  use: {
    baseURL: 'http://127.0.0.1:18889',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    ...devices['Desktop Chrome']
  },
  webServer: {
    command: 'python serve_browser.py --root ../../control-center',
    url: 'http://127.0.0.1:18889/gateway/health',
    timeout: 90000,
    reuseExistingServer: false,
    env: { CI: 'true', GITHUB_ACTIONS: 'true' }
  },
  outputDir: 'test-results'
});
