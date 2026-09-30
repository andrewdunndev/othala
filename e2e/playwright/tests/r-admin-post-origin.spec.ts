// R — a real browser POST to the admin panel is not refused by the origin check.

import { test, expect } from '../fixtures';
import { adminAal2Context } from '../fixtures';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';

async function getIdentityState(kratosAdminURL: string, id: string): Promise<string> {
  return ((await readIdentity(kratosAdminURL, id)) as { state?: string }).state ?? 'active';
}

test('R1 — admin deactivate/reactivate via a real browser click must not 403 (regression for #5)', async ({
  browser,
  baseURL,
  kratosAdminURL,
}) => {
  const actingAdmin = await createIdentityWithPassword({
    email: 'r1.acting-admin@othala.test',
    username: 'r1.acting.admin',
    displayName: 'R1 Acting Admin',
    groups: [],
    isAdmin: true,
    kratosAdminURL,
  });
  const target = await createIdentityWithPassword({
    email: 'r1.target@othala.test',
    username: 'r1.target',
    displayName: 'R1 Target',
    groups: [],
    kratosAdminURL,
  });
  console.log('[R1] acting admin:', actingAdmin.id, '| target:', target.id);

  const ctx = await adminAal2Context({
    browser,
    email: actingAdmin.email,
    password: TEST_PASSWORD,
    baseURL: baseURL!,
  });

  try {
    const page = await ctx.newPage();
    const targetUrl = `${baseURL}/admin/users/${target.id}`;

    await page.goto(targetUrl, { waitUntil: 'networkidle' });
    await expect(page.locator('h1'), 'R1: admin page must render the target identity').toContainText('r1.target');

    const deactivateBtn = page.getByRole('button', { name: 'Deactivate' });
    await expect(deactivateBtn, 'R1: Deactivate button must be visible').toBeVisible({ timeout: 10_000 });

    const [deactivateResp] = await Promise.all([
      page.waitForResponse((r) => r.url() === targetUrl && r.request().method() === 'POST'),
      deactivateBtn.click(),
    ]);

    console.log('[R1] deactivate POST →', deactivateResp.status());
    expect(
      deactivateResp.status(),
      `R1 (regression for #5): deactivate POST must not 403 — a 403 here means Referrer-Policy is ` +
      `suppressing Origin again and Astro's checkOrigin is firing before app code; got ${deactivateResp.status()}`,
    ).not.toBe(403);
    expect(
      deactivateResp.status(),
      `R1: deactivate POST must succeed (200, same-page re-render); got ${deactivateResp.status()}`,
    ).toBe(200);

    await expect(
      page.getByText(/marked inactive/i),
      'R1: page must show the "marked inactive" success notice after deactivate',
    ).toBeVisible();

    expect(
      await getIdentityState(kratosAdminURL, target.id),
      'R1: target identity state must be "inactive" after deactivate',
    ).toBe('inactive');

    const reactivateBtn = page.getByRole('button', { name: 'Reactivate' });
    await expect(reactivateBtn, 'R1: Reactivate button must be visible after deactivate').toBeVisible({ timeout: 10_000 });

    const [reactivateResp] = await Promise.all([
      page.waitForResponse((r) => r.url() === targetUrl && r.request().method() === 'POST'),
      reactivateBtn.click(),
    ]);

    console.log('[R1] reactivate POST →', reactivateResp.status());
    expect(
      reactivateResp.status(),
      `R1 (regression for #5): reactivate POST must not 403; got ${reactivateResp.status()}`,
    ).not.toBe(403);
    expect(
      reactivateResp.status(),
      `R1: reactivate POST must succeed (200); got ${reactivateResp.status()}`,
    ).toBe(200);

    await expect(
      page.getByText(/restored to active/i),
      'R1: page must show the "restored to active" success notice after reactivate',
    ).toBeVisible();

    expect(
      await getIdentityState(kratosAdminURL, target.id),
      'R1: target identity state must be back to "active" after reactivate (clean throwaway)',
    ).toBe('active');

    console.log('[R1] PASS — admin mutation reachable via a real browser POST; throwaway restored to active');
  } finally {
    await ctx.close();
  }
});
