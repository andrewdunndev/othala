/**
 * D — Admin → /admin → AAL2 step-up enforced; admin at AAL2 actually reaches /admin.
 *
 * D1 (INV-1): An identity with metadata_admin.admin=true at AAL1 (password only)
 *   visits /admin and is redirected to the AAL2 step-up. The step-up must target
 *   the configured host (not the old hardcoded dag.dunn.dev).
 *
 * D2 (INV-3): An admin who completes AAL2 (TOTP enrollment + step-up via
 *   adminAal2Context) ACTUALLY reaches /admin (200 + admin page content).
 *   This proves the gate is not always-deny: the marker GRANTS when both
 *   conditions are satisfied (AAL2 + admin marker).
 *
 * Together D1+D2 bound the gate from both sides:
 *   - AAL2 alone is not sufficient (INV-2, tested in q-aal2-nonadmin-denied).
 *   - Marker alone is not sufficient (INV-1, D1 — even with the marker, AAL1 denies).
 *   - AAL2 + marker grants (INV-3, D2).
 */

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';
import { adminAal2Context } from '../fixtures';

// ─── D1: Admin at AAL1 → step-up redirect ────────────────────────────────────
test('D1 — INV-1: admin at AAL1 is redirected to AAL2 step-up (marker alone insufficient)', async ({
  browser,
  baseURL,
  admin,
}) => {
  const ctx = await browser.newContext();

  try {
    // Login as admin at AAL1 (password only — no second factor).
    await loginViaJsonApi(
      ctx,
      { identifier: admin.email, password: admin.password },
      baseURL,
    );

    // requireAdminSession check (b) fires before check (c): an AAL1 session
    // gets the step-up redirect before the marker is ever consulted.
    // maxRedirects:0 captures the first Location so we can assert aal=aal2.
    const resp = await ctx.request.get(`${baseURL}/admin`, { maxRedirects: 0 });
    const loc = resp.headers()['location'] ?? '';
    console.log('[D1] /admin (AAL1 admin) →', resp.status(), loc);

    // INV-1: even an admin with the marker is denied at AAL1.
    expect(
      /aal=aal2/.test(loc),
      `D1 (INV-1): admin at AAL1 must be redirected to AAL2 step-up; got ${resp.status()} ${loc}`,
    ).toBe(true);

    // Portability: the step-up must use the configured host, not the old
    // hardcoded dag.dunn.dev (the admin.ts portability bug fixed in the config pass).
    expect(
      loc.includes('dag.dunn.dev'),
      `D1 (portability): step-up must not target dag.dunn.dev; got ${loc}`,
    ).toBe(false);
  } finally {
    await ctx.close();
  }
});

// ─── D2: Admin at AAL2 → /admin → 200 + admin content ───────────────────────
test('D2 — INV-3: admin at AAL2 reaches /admin (marker GRANTS, gate is not always-deny)', async ({
  browser,
  baseURL,
  admin,
}) => {
  // adminAal2Context: AAL1 login → TOTP enrollment via settings flow →
  // AAL2 step-up → session with authenticator_assurance_level=aal2.
  // The returned context has a session cookie that satisfies both conditions:
  //   (b) AAL2 server-side — session.authenticator_assurance_level === 'aal2'
  //   (c) admin marker — identity.metadata_admin.admin === true (seeded by validate.sh)
  const ctx = await adminAal2Context({
    browser,
    email: admin.email,
    password: admin.password,
    baseURL,
  });

  try {
    // GET /admin with an AAL2 admin session: requireAdminSession should pass
    // both checks (b) and (c) and return the session (not a redirect).
    // Follow redirects to land on the final page (admin UI renders under /admin).
    const resp = await ctx.request.get(`${baseURL}/admin`, { maxRedirects: 10 });
    const status = resp.status();
    const finalUrl = resp.url();
    console.log('[D2] GET /admin (AAL2 admin) →', status, finalUrl);

    // INV-3 primary: the admin actually reaches /admin — not an error, not a
    // step-up, not a redirect to login. A 200 proves the gate GRANTS.
    expect(
      status,
      `D2 (INV-3): admin at AAL2 must receive 200 at /admin; got ${status} (url: ${finalUrl})`,
    ).toBe(200);

    // INV-3 content: the page must contain admin-specific content, ruling out
    // a 200-but-wrong-page scenario (e.g. the login page returning 200 instead
    // of redirecting). We assert any characteristic admin heading or element.
    const body = await resp.text();
    const hasAdminContent =
      /admin/i.test(body) &&
      // The admin page should contain a link or heading referencing users or admin
      // management. Adjust the selector if the admin layout changes.
      (/Users?/i.test(body) || /Dashboard/i.test(body) || /admin-panel/i.test(body));

    expect(
      hasAdminContent,
      `D2 (INV-3): /admin must render admin-specific page content; got ${body.slice(0, 300)}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});
