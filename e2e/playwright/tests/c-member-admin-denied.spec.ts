/**
 * C — Non-admin member denied at /admin (browser-test.mjs assertion C).
 *
 * A member (bt2@othala.test) who is NOT on OTHALA_ADMIN_IDS visits /admin.
 * The requireAdminSession middleware in the othala app must deny access.
 * Expected: the URL after redirect contains reason=not-admin OR routes to
 * /auth/error (the app's error page for the allowlist gate).
 *
 * The member has a valid Kratos session (AAL1, password) so the check is NOT
 * the "unauthenticated" branch — it is specifically the allowlist check:
 * "authenticated but not on the admin allowlist".
 */

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';

test('C — non-admin member is denied at /admin with reason=not-admin', async ({
  browser,
  baseURL,
  member,
}) => {
  const ctx = await browser.newContext();

  try {
    // Login as member (NOT an admin subject).
    await loginViaJsonApi(
      ctx,
      { identifier: member.email, password: member.password },
      baseURL,
    );

    const page = await ctx.newPage();

    // Navigate to /admin. The requireAdminSession middleware will check the
    // session's identity id against OTHALA_ADMIN_IDS. bt2's id is not on the
    // list → redirect to error URL with reason=not-admin.
    await page.goto(`${baseURL}/admin`, { waitUntil: 'networkidle', timeout: 30_000 });

    const finalUrl = page.url();
    console.log('[C] landed at:', finalUrl);

    await page.screenshot({ path: '/out/c-member-admin-denied.png', fullPage: true }).catch(() => {});

    expect(
      /reason=not-admin/.test(finalUrl) || /\/auth\/error/.test(finalUrl),
      `C: non-admin member must be denied at /admin; landed at ${finalUrl}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});
