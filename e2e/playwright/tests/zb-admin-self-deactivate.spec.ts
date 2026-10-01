// ZB — the admin console refuses to deactivate the acting admin.

import { test, expect, adminAal2Context } from '../fixtures';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';

const SELF_DEACTIVATE_REFUSAL = 'You cannot deactivate your own identity via the UI. Have another admin do it.';

test('ZB1 — deactivating your own identity is refused', async ({ browser, baseURL, kratosAdminURL }) => {
  const suffix = `zb1.${Date.now()}`;
  const admin = await createIdentityWithPassword({
    email: `self.deactivate.${suffix}@othala.test`,
    username: `selfdeact.${suffix}`,
    displayName: 'Self Deactivate',
    groups: [],
    isAdmin: true,
    kratosAdminURL,
  });
  const ctx = await adminAal2Context({ browser, email: admin.email, password: TEST_PASSWORD, baseURL: baseURL! });
  try {
    const page = await ctx.newPage();
    const targetUrl = `${baseURL}/admin/users/${admin.id}`;
    await page.goto(targetUrl, { waitUntil: 'networkidle' });
    await page.locator('summary', { hasText: 'Danger zone' }).click();
    await page.locator('summary', { hasText: 'Turn off sign-in' }).click();
    const [resp] = await Promise.all([
      page.waitForResponse((r) => r.url().startsWith(targetUrl) && r.request().method() === 'POST'),
      page.locator('form.confirm').getByRole('button', { name: 'Turn off sign-in' }).click(),
    ]);
    expect(resp.status(), 'refusal re-renders the page').toBe(200);
    await expect(page.getByText(SELF_DEACTIVATE_REFUSAL)).toBeVisible();

    expect(((await readIdentity(kratosAdminURL, admin.id)) as { state: string }).state).toBe('active');
  } finally {
    await ctx.close();
  }
});
