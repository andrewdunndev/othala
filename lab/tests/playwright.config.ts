import { defineConfig } from "@playwright/test";

const DOMAIN = process.env.DOMAIN || "test.dunn.dev";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  timeout: 60_000,
  retries: 1,
  use: {
    baseURL: `https://auth.${DOMAIN}`,
    ignoreHTTPSErrors: true,
    screenshot: "only-on-failure",
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: {
        browserName: "chromium",
      },
    },
  ],
});
