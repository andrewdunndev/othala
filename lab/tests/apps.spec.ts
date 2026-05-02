import { test, expect, Page } from "@playwright/test";

const DOMAIN = process.env.DOMAIN || "test.dunn.dev";
const AUTH_URL = `https://auth.${DOMAIN}`;
const ADMIN_USER = "akadmin";
const ADMIN_PASS = process.env.AUTHENTIK_BOOTSTRAP_PASSWORD || "test-admin-password";

// Helper: login to Authentik
async function loginToAuthentik(page: Page, username: string, password: string) {
  await page.goto(`${AUTH_URL}/if/flow/dunn-authentication/`);
  await page.getByLabel(/username|email/i).fill(username);
  await page.getByRole("button", { name: /next|continue|sign in/i }).click();
  await page.getByLabel(/password/i).fill(password);
  await page.getByRole("button", { name: /sign in|continue|log in/i }).click();
  await page.waitForURL(/\/if\/user\//);
}

// --- OIDC Apps: Unauthenticated redirect tests ---

const oidcApps = [
  { name: "Vaultwarden", subdomain: "keep" },
  { name: "Mealie", subdomain: "larder" },
  { name: "Audiobookshelf", subdomain: "listen" },
  { name: "Immich", subdomain: "memory" },
];

for (const app of oidcApps) {
  test.describe(`${app.name} (${app.subdomain})`, () => {
    test(`${app.name} is reachable`, async ({ page }) => {
      const response = await page.goto(`https://${app.subdomain}.${DOMAIN}/`);
      // Should get some response (200, 302, etc.) — not a connection error
      expect(response).not.toBeNull();
      expect(response!.status()).toBeLessThan(500);
    });
  });
}

// --- Forward Auth: Navidrome ---

test.describe("Navidrome (tune) — forward auth", () => {
  test("Unauthenticated request redirects to Authentik", async ({ page }) => {
    const response = await page.goto(`https://tune.${DOMAIN}/`);
    // Should redirect to Authentik for login
    // The final URL should contain auth.test.dunn.dev
    const url = page.url();
    expect(url).toContain(`auth.${DOMAIN}`);
  });

  test("Authenticated user can access Navidrome", async ({ page }) => {
    // Login to Authentik first
    await loginToAuthentik(page, ADMIN_USER, ADMIN_PASS);

    // Now visit Navidrome — should pass through forward auth
    await page.goto(`https://tune.${DOMAIN}/`);
    // Should NOT be redirected to Authentik
    const url = page.url();
    expect(url).toContain(`tune.${DOMAIN}`);
  });
});

// --- Jellyfin (LDAP) ---

test.describe("Jellyfin (cinema) — LDAP", () => {
  test("Jellyfin is reachable", async ({ page }) => {
    const response = await page.goto(`https://cinema.${DOMAIN}/`);
    expect(response).not.toBeNull();
    expect(response!.status()).toBeLessThan(500);
  });
});

// --- Group-based access control ---
// deploy.sh sets all test user passwords to TEST_USER_PASSWORD.

const TEST_PASS = process.env.TEST_USER_PASSWORD || "bench-test-pass";

test.describe("Access control", () => {
  test("test.family (access-listen) can reach tune via forward auth", async ({
    page,
  }) => {
    // test.family is in access-tune group → should pass forward auth
    await loginToAuthentik(page, "test.family", TEST_PASS);
    await page.goto(`https://tune.${DOMAIN}/`);
    const url = page.url();
    expect(url).toContain(`tune.${DOMAIN}`);
  });

  test("test.friend (no access-keep) is denied keep", async ({ page }) => {
    // test.friend is NOT in access-keep → Authentik should deny at the
    // provider authorization step (policy check fails)
    await loginToAuthentik(page, "test.friend", TEST_PASS);
    await page.goto(`https://keep.${DOMAIN}/`);
    // Authentik shows a "denied" page or the app never loads
    const url = page.url();
    // Should still be on the Authentik domain (denied before redirect to app)
    expect(url).toContain(`auth.${DOMAIN}`);
  });
});
