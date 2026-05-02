import { test, expect } from "@playwright/test";

const DOMAIN = process.env.DOMAIN || "test.dunn.dev";
const AUTH_URL = `https://auth.${DOMAIN}`;
const ADMIN_USER = "akadmin";
const ADMIN_PASS = process.env.AUTHENTIK_BOOTSTRAP_PASSWORD || "test-admin-password";

test.describe("Authentik Authentication", () => {
  test("Authentik login page loads", async ({ page }) => {
    await page.goto(AUTH_URL);
    // Should see the Authentik login page
    await expect(page).toHaveTitle(/authentik|Sign in|dunn/i);
  });

  test("Admin can log in with password", async ({ page }) => {
    await page.goto(`${AUTH_URL}/if/flow/dunn-authentication/`);

    // Fill in username
    await page.getByLabel(/username|email/i).fill(ADMIN_USER);
    await page.getByRole("button", { name: /next|continue|sign in/i }).click();

    // Fill in password
    await page.getByLabel(/password/i).fill(ADMIN_PASS);
    await page.getByRole("button", { name: /sign in|continue|log in/i }).click();

    // Should land on the user interface
    await page.waitForURL(/\/if\/user\//);
    await expect(page.url()).toContain("/if/user/");
  });

  test("Admin can access admin interface", async ({ page }) => {
    // Login first
    await page.goto(`${AUTH_URL}/if/flow/dunn-authentication/`);
    await page.getByLabel(/username|email/i).fill(ADMIN_USER);
    await page.getByRole("button", { name: /next|continue|sign in/i }).click();
    await page.getByLabel(/password/i).fill(ADMIN_PASS);
    await page.getByRole("button", { name: /sign in|continue|log in/i }).click();
    await page.waitForURL(/\/if\/user\//);

    // Navigate to admin
    await page.goto(`${AUTH_URL}/if/admin/`);
    await expect(page.url()).toContain("/if/admin/");
  });

  test("Session persists after page reload", async ({ page }) => {
    // Login
    await page.goto(`${AUTH_URL}/if/flow/dunn-authentication/`);
    await page.getByLabel(/username|email/i).fill(ADMIN_USER);
    await page.getByRole("button", { name: /next|continue|sign in/i }).click();
    await page.getByLabel(/password/i).fill(ADMIN_PASS);
    await page.getByRole("button", { name: /sign in|continue|log in/i }).click();
    await page.waitForURL(/\/if\/user\//);

    // Reload and verify still logged in
    await page.reload();
    await expect(page.url()).toContain("/if/user/");
  });
});
