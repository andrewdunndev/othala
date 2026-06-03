/**
 * D — Admin → /admin → AAL2 step-up enforced (browser-test.mjs assertion D).
 *
 * An identity on OTHALA_ADMIN_SUBJECTS (admin@othala.test) logs in with
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

    const page = await ctx.newPage();

    // Collect any navigation to the dag.dunn.dev host (the portability bug
    // from the old admin.ts — now fixed). If this intercept fires, the test
    // note below will surface it.
    let oldHostIntercept: string | null = null;
    await page.route('https://dag.dunn.dev/**', (route) => {
      oldHostIntercept = route.request().url();
      // Fulfill so the browser doesn't hang, then assert below.
      route.fulfill({ status: 200, contentType: 'text/plain', body: 'old-host-intercept' });
    });

    // Navigate to /admin as an AAL1 admin session.
    await page.goto(`${baseURL}/admin`, { waitUntil: 'domcontentloaded', timeout: 30_000 });

    const finalUrl = page.url();
    console.log('[D] landed at:', finalUrl);
    if (oldHostIntercept) {
      console.warn('[D] PORTABILITY BUG: step-up redirect went to dag.dunn.dev:', oldHostIntercept);
    }

    await page.screenshot({ path: '/out/d-admin-aal2-stepup.png', fullPage: true }).catch(() => {});

    // Primary assertion: aal=aal2 appears in the landing URL.
    // After convergence, the step-up URL is under auth.othala.test, so the
    // browser can follow it without an intercept.
    expect(
      /aal=aal2/.test(finalUrl) || /aal=aal2/.test(oldHostIntercept ?? ''),
      `D: admin at AAL1 must trigger AAL2 step-up; landed at ${finalUrl}` +
        (oldHostIntercept ? ` (old-host intercept: ${oldHostIntercept})` : ''),
    ).toBe(true);

    // Secondary assertion: step-up must NOT require the old hardcoded dag.dunn.dev.
    expect(
      oldHostIntercept,
      'D (portability): step-up redirect must NOT target dag.dunn.dev — use OTHALA_PUBLIC_URL',
    ).toBeNull();
  } finally {
    await ctx.close();
  }
});
