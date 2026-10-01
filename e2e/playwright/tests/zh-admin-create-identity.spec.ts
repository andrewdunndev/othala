// ZH — the admin console's "New user" form creates an identity and issues an enrollment link and code.
// The portal sends no schema_id, so this only passes when Kratos applies identity.default_schema_id itself.

import { test, expect, adminAal2Context } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';

test('ZH1 — creating an identity through /admin/users/new succeeds and issues a link and code', async ({
  browser,
  baseURL,
  kratosAdminURL,
}) => {
  const suffix = Date.now();
  const admin = await createIdentityWithPassword({
    email: `zh1.admin.${suffix}@othala.test`,
    username: `zh1.admin.${suffix}`,
    displayName: 'ZH1 Admin',
    groups: [],
    isAdmin: true,
    kratosAdminURL,
  });
  const newUser = { username: `zh1.created.${suffix}`, email: `zh1.created.${suffix}@othala.test` };

  const ctx = await adminAal2Context({ browser, email: admin.email, password: TEST_PASSWORD, baseURL: baseURL! });
  try {
    const page = await ctx.newPage();
    const formUrl = `${baseURL}/admin/users/new`;
    await page.goto(formUrl, { waitUntil: 'networkidle' });

    await page.locator('#username').fill(newUser.username);
    await page.locator('#email').fill(newUser.email);
    const [resp] = await Promise.all([
      page.waitForResponse((r) => r.url() === formUrl && r.request().method() === 'POST'),
      page.getByRole('button', { name: /Create identity/ }).click(),
    ]);
    expect(resp.status(), 'ZH1: create POST must re-render the page, not 403 or 500').toBe(200);

    await expect(
      page.getByText(`Identity created for ${newUser.username}.`),
      'ZH1: page must show the success notice, not an error notice',
    ).toBeVisible();
    await expect(page.locator('.notice-danger'), 'ZH1: no error notice').toHaveCount(0);
    await expect(page.locator('#recoveryUrl'), 'ZH1: an enrollment link is shown').not.toHaveValue('');
    await expect(page.locator('#recoveryCode'), 'ZH1: a recovery code is shown').toHaveValue(/^\d{6}$/);

    const lookup = await fetch(
      `${kratosAdminURL}/admin/identities?credentials_identifier=${encodeURIComponent(newUser.email)}`,
    );
    const found = (await lookup.json()) as { id: string; schema_id: string }[];
    expect(found, 'ZH1: Kratos must hold the new identity').toHaveLength(1);
    expect(found[0].schema_id, 'ZH1: Kratos applied its default schema').toBe('family');
  } finally {
    await ctx.close();
  }
});
