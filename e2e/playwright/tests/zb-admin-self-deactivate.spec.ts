// ZB — the admin console refuses to deactivate the acting admin.

import { test, expect, adminAal2Context } from '../fixtures';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';
import { csrfTokenFor, postAdminAction } from '../actions/admin-post';

const SELF_DEACTIVATE_REFUSAL = 'You cannot deactivate your own identity via the UI. Have another admin do it.';

test('ZB1 — turning off your own sign-in is not offered, and a hand-made POST is refused', async ({ browser, baseURL, kratosAdminURL }) => {
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
    await expect(page.getByText(/can't turn off your own sign-in/i), 'the page says why instead of offering it').toBeVisible();
    await expect(page.locator('summary', { hasText: 'Turn off sign-in' }), 'no turn-off action is offered').toHaveCount(0);

    // The server guard stands on its own: a token from another person's page, posted at the admin's own page.
    const other = await createIdentityWithPassword({
      email: `other.${suffix}@othala.test`,
      username: `other.${suffix}`,
      displayName: 'Other Person',
      groups: [],
      kratosAdminURL,
    });
    await page.goto(`${baseURL}/admin/users/${other.id}`, { waitUntil: 'networkidle' });
    const token = await csrfTokenFor(page, 'deactivate');
    const resp = await postAdminAction(ctx, baseURL!, admin.id, { csrf_token: token, action: 'deactivate' });
    expect(resp.status(), 'refusal re-renders the page').toBe(200);
    expect(await resp.text()).toContain(SELF_DEACTIVATE_REFUSAL);

    expect(((await readIdentity(kratosAdminURL, admin.id)) as { state: string }).state).toBe('active');
  } finally {
    await ctx.close();
  }
});
