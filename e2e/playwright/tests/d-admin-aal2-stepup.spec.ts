/**
 * D — Admin → /admin → AAL2 step-up enforced (browser-test.mjs assertion D).
 *
 * An identity on OTHALA_ADMIN_IDS (admin@othala.test) logs in with
 * password only (AAL1) and visits /admin. The requireAdminSession middleware
 * detects AAL1 and redirects to a Kratos login flow requesting AAL2 (step-up
 * with a second factor). The redirect must target auth.othala.test (NOT the
 * old hardcoded dag.dunn.dev — the portability bug noted in browser-test.mjs
 * is fixed by the config convergence pass).
 *
 * Assertion: the URL the browser lands on after /admin contains aal=aal2 as a
 * query parameter (the Kratos /self-service/login/browser?aal=aal2 step-up URL).
 *
 * After the config convergence, the admin.ts step-up redirect is derived from
 * OTHALA_PUBLIC_URL (=http://auth.othala.test in the e2e env) rather than a
 * hardcoded dag.dunn.dev literal, so:
 *   - the redirect target is within auth.othala.test (observable by the browser),
 *   - no page.route() intercept for dag.dunn.dev is needed,
 *   - aal=aal2 appears in the URL the browser lands on.
 */

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';

test('D — allowlisted admin at AAL1 is redirected to AAL2 step-up at /admin', async ({
  browser,
  baseURL,
  admin,
}) => {
  const ctx = await browser.newContext();

  try {
    // Login as admin at AAL1 (password only — no second factor submitted).
    await loginViaJsonApi(
      ctx,
      { identifier: admin.email, password: admin.password },
      baseURL,
    );

    // Assert OUR admin gate ISSUES the AAL2 step-up redirect. We do NOT follow
    // it into Kratos: the seeded admin has no second factor enrolled, so Kratos's
    // aal2 login flow would error (/auth/error) — that is a Kratos-UI concern, not
    // what this test covers. requireAdminSession should 30x an AAL1 admin to a
    // Kratos aal2 login-flow init; maxRedirects:0 captures that first Location.
    const resp = await ctx.request.get(`${baseURL}/admin`, { maxRedirects: 0 });
    const loc = resp.headers()['location'] ?? '';
    console.log('[D] /admin (AAL1 admin) →', resp.status(), loc);

    expect(
      /aal=aal2/.test(loc),
      `D: admin at AAL1 must be redirected to AAL2 step-up; got ${resp.status()} ${loc}`,
    ).toBe(true);

    // Portability: the step-up must use the configured host, NOT the old
    // hardcoded dag.dunn.dev (the admin.ts bug fixed in the config pass).
    expect(
      loc.includes('dag.dunn.dev'),
      `D (portability): step-up must not target dag.dunn.dev; got ${loc}`,
    ).toBe(false);
  } finally {
    await ctx.close();
  }
});
