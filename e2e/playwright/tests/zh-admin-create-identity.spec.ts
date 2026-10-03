// ZH — the admin console issues an enrollment link and code for a new person, and never for an admin.
// ZH1: the portal sends no schema_id, so it only passes when Kratos applies identity.default_schema_id itself.

import { test, expect, adminAal2Context } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { csrfTokenFor, postAdminAction } from '../actions/admin-post';

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

    await page.locator('#displayName').fill('ZH1 Created');
    await page.locator('#email').fill(newUser.email);
    await page.locator('summary', { hasText: 'More options' }).click();
    await page.locator('#username').fill(newUser.username);
    const [resp] = await Promise.all([
      page.waitForResponse((r) => r.url() === formUrl && r.request().method() === 'POST'),
      page.getByRole('button', { name: 'Add person' }).click(),
    ]);
    expect(resp.status(), 'ZH1: create POST must re-render the page, not 403 or 500').toBe(200);

    await expect(
      page.getByRole('heading', { name: 'ZH1 is ready' }),
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

test('ZH2 — an admin-marked target is offered no setup link, and a hand-made POST is refused server-side', async ({
  browser,
  baseURL,
  kratosAdminURL,
}) => {
  const suffix = Date.now();
  const admin = await createIdentityWithPassword({
    email: `zh2.admin.${suffix}@othala.test`,
    username: `zh2.admin.${suffix}`,
    displayName: 'ZH2 Admin',
    groups: [],
    isAdmin: true,
    kratosAdminURL,
  });
  const adminTarget = await createIdentityWithPassword({
    email: `zh2.admin-target.${suffix}@othala.test`,
    username: `zh2.admin.target.${suffix}`,
    displayName: 'ZH2 Admin Target',
    groups: [],
    isAdmin: true,
    kratosAdminURL,
  });
  const bystander = await createIdentityWithPassword({
    email: `zh2.bystander.${suffix}@othala.test`,
    username: `zh2.bystander.${suffix}`,
    displayName: 'ZH2 Bystander',
    groups: [],
    kratosAdminURL,
  });

  const ctx = await adminAal2Context({ browser, email: admin.email, password: TEST_PASSWORD, baseURL: baseURL! });
  try {
    const page = await ctx.newPage();
    await page.goto(`${baseURL}/admin/users/${adminTarget.id}`, { waitUntil: 'networkidle' });
    await expect(page.locator('h1'), 'ZH2: admin page must render the admin-target identity').toContainText('ZH2 Admin Target');
    await expect(page.getByText(/A household admin cannot be sent a setup link here/i), 'ZH2: the no-setup-link note is shown').toBeVisible();
    await expect(page.getByRole('button', { name: 'Get setup link' }), 'ZH2: no setup link action is offered').toHaveCount(0);

    await page.goto(`${baseURL}/admin/users/${bystander.id}`, { waitUntil: 'networkidle' });
    const token = await csrfTokenFor(page, 'issue-recovery');
    expect(token, 'ZH2: the bystander page carries a setup-link token').not.toBe('');
    const resp = await postAdminAction(ctx, baseURL!, adminTarget.id, { csrf_token: token, action: 'issue-recovery' });
    expect(resp.status(), 'ZH2: the refusal is a normal re-render, not a 403').toBe(200);
    const html = await resp.text();
    expect(html, 'ZH2: the server refuses a setup link for an admin').toMatch(/setup link for an admin cannot be made here/);
    expect(html, 'ZH2: no setup link is rendered').not.toContain('id="recoveryUrl"');
  } finally {
    await ctx.close();
  }
});
