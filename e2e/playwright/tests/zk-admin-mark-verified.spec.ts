// ZK — "Mark verified" on the person page really verifies the email address in Kratos, and the badge follows.

import { test, expect, adminAal2Context } from '../fixtures';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';

test('ZK1 — marking an email verified writes the verified address and flips the badge', async ({ browser, baseURL, kratosAdminURL }) => {
  const suffix = `zk1.${Date.now()}`;
  const admin = await createIdentityWithPassword({
    email: `admin.${suffix}@othala.test`,
    username: `admin.${suffix}`,
    displayName: 'ZK Admin',
    groups: [],
    isAdmin: true,
    kratosAdminURL,
  });
  const target = await createIdentityWithPassword({
    email: `target.${suffix}@othala.test`,
    username: `target.${suffix}`,
    displayName: 'ZK Target',
    groups: [],
    kratosAdminURL,
  });
  const verifiedOf = async () =>
    ((await readIdentity(kratosAdminURL, target.id)) as { verifiable_addresses: Array<{ value: string; verified: boolean }> })
      .verifiable_addresses.find((a) => a.value === target.email.toLowerCase())?.verified;
  expect(await verifiedOf(), 'ZK1: the seeded address starts unverified').toBe(false);

  const ctx = await adminAal2Context({ browser, email: admin.email, password: TEST_PASSWORD, baseURL: baseURL! });
  try {
    const page = await ctx.newPage();
    const targetUrl = `${baseURL}/admin/users/${target.id}`;
    await page.goto(targetUrl, { waitUntil: 'networkidle' });
    await expect(page.locator('.badges')).toContainText('Unverified email');

    await page.locator('summary', { hasText: 'Mark verified' }).click();
    const [resp] = await Promise.all([
      page.waitForResponse((r) => r.url().startsWith(targetUrl) && r.request().method() === 'POST'),
      page.locator('form.confirm').getByRole('button', { name: 'Mark verified' }).click(),
    ]);
    expect(resp.status(), 'ZK1: the POST re-renders the page').toBe(200);

    expect(await verifiedOf(), 'ZK1: Kratos now holds the address as verified').toBe(true);
    await expect(page.locator('.badges')).toContainText('Verified email');
    await expect(page.locator('.badges')).not.toContainText('Unverified');
    await expect(page.locator('summary', { hasText: 'Mark verified' }), 'ZK1: the action is gone once verified').toHaveCount(0);
  } finally {
    await ctx.close();
  }
});
