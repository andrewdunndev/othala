/**
 * ZB — the admin console refuses to deactivate the acting admin.
 *
 *   ZB1 — an admin opens their own identity and presses Deactivate; the page
 *         shows the neutral refusal and the admin API still reports the
 *         identity active.
 *
 * The admin is seeded per run so the refusal never depends on another admin.
 */

import { test, expect, adminAal2Context } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';

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
    const [resp] = await Promise.all([
      page.waitForResponse((r) => r.url().startsWith(targetUrl) && r.request().method() === 'POST'),
      page.getByRole('button', { name: 'Deactivate', exact: true }).click(),
    ]);
    expect(resp.status(), 'refusal re-renders the page').toBe(200);
    await expect(page.getByText(SELF_DEACTIVATE_REFUSAL)).toBeVisible();

    const stored = await fetch(`${kratosAdminURL}/admin/identities/${admin.id}`);
    expect(stored.ok, 'admin API identity read').toBe(true);
    expect(((await stored.json()) as { state: string }).state).toBe('active');
  } finally {
    await ctx.close();
  }
});
