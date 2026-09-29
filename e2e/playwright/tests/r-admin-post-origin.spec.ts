/**
 * R — Admin panel: a REAL browser POST must not 403 (regression for
 * work item #5 — Referrer-Policy: no-referrer broke checkOrigin).
 *
 * Bug: portal/src/middleware.ts set `Referrer-Policy: no-referrer` on every
 * response. Chromium responds to that by sending `Origin: null` on a
 * same-origin form-POST *navigation* (not a fetch() call — this is a
 * navigation-stack behaviour tied to the RESPONSE header of the page that
 * hosts the form). Astro's built-in `security.checkOrigin` CSRF gate then
 * 403s the request before any app code — including the app's own per-action
 * csrf.ts token layer — ever runs. Every state-changing admin POST
 * (issue-recovery, force-relogin, deactivate, delete, grant/revoke-admin,
 * profile save) was unreachable from a real browser.
 *
 * Why the existing suite missed this: H1-H3 (h-member-admin-post.spec.ts)
 * DO drive POSTs against /admin/users/*, but via `ctx.request.post()` with
 * a manually-set `Origin` header (`headers: { Origin: origin }`) — that
 * proves the guard ORDER (checkOrigin before requireAdminSession), but it
 * can never catch #5, because a hand-set Origin header sidesteps the exact
 * browser-navigation computation the bug lives in. No existing spec drives
 * an admin mutation via an actual rendered page + a real button click.
 *
 * R1 closes that gap: a real AAL2 admin session opens the rendered
 * /admin/users/<id> page (so the response carries the middleware's actual
 * security headers) and clicks the real "Deactivate" / "Reactivate"
 * buttons — real document-navigation POSTs, Chromium computing Origin from
 * scratch. Pre-fix this 403s at the edge; post-fix (Referrer-Policy:
 * same-origin) it reaches the app and the mutation completes. Uses a
 * dedicated throwaway target identity (deactivate + reactivate leaves it
 * exactly as found) and a dedicated throwaway acting-admin (isAdmin) so
 * this spec doesn't share TOTP-enrollment state with the worker-scoped
 * `admin` fixture other specs depend on.
 */

import { test, expect } from '../fixtures';
import { adminAal2Context } from '../fixtures';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';

/** Read an identity's `state` via the Kratos admin API (ground truth for "the effect"). */
async function getIdentityState(kratosAdminURL: string, id: string): Promise<string> {
  return ((await readIdentity(kratosAdminURL, id)) as { state?: string }).state ?? 'active';
}

test('R1 — admin deactivate/reactivate via a real browser click must not 403 (regression for #5)', async ({
  browser,
  baseURL,
  kratosAdminURL,
}) => {
  // Dedicated throwaway identities: an acting admin (isAdmin marker) and a
  // separate mutation target. Kept isolated from the shared worker-scoped
  // `admin` fixture so this spec's own TOTP enrollment can't collide with it.
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

  // adminAal2Context: AAL1 login → TOTP enrollment → AAL2 step-up. Generic
  // over any identity/password — not tied to the shared `admin` fixture.
  const ctx = await adminAal2Context({
    browser,
    email: actingAdmin.email,
    password: TEST_PASSWORD,
    baseURL: baseURL!,
  });

  try {
    const page = await ctx.newPage();
    const targetUrl = `${baseURL}/admin/users/${target.id}`;

    // Real GET navigation — the response carries the middleware's actual
    // security headers (Referrer-Policy included), exactly as a real
    // operator's browser would receive them.
    await page.goto(targetUrl, { waitUntil: 'networkidle' });
    await expect(page.locator('h1'), 'R1: admin page must render the target identity').toContainText('r1.target');

    // Click "Deactivate" — a REAL <form method="post"> submit with no
    // action= attribute (posts back to the current URL). Chromium computes
    // Origin from the page's Referrer-Policy header here, not from a header
    // we set by hand (unlike H1-H3's ctx.request.post probes).
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

    // Ground truth for "the effect": the identity really is inactive, not
    // just a page that happened to render a success notice.
    expect(
      await getIdentityState(kratosAdminURL, target.id),
      'R1: target identity state must be "inactive" after deactivate',
    ).toBe('inactive');

    // Restore: click "Reactivate" (rendered now that state === 'inactive').
    // Same real-browser-navigation check applies a second time.
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
