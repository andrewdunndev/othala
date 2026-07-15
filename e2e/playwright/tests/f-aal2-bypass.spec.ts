/**
 * F — AAL2 bypass attempts (adversarial / negative).
 *
 * Guard under attack:
 *   portal/src/lib/admin.ts:requireAdminSession
 *   — specifically the AAL2 check (b):
 *       if (session.authenticator_assurance_level !== 'aal2')
 *           return astro.redirect(browserFlows.login({ ... aal: 'aal2', ... }))
 *
 * An identity with metadata_admin.admin=true (ADR 08 marker, admin@othala.test)
 * with a valid AAL1 session (password-only login, no second factor enrolled or
 * presented) MUST be denied every /admin/* mutation path. No bypass via:
 *   F1 — direct GET /admin (covered by spec D; repeated here in request form)
 *   F2 — direct POST to /admin/users/new (a create-user mutation)
 *   F3 — return_to parameter manipulation on the step-up redirect
 *        (the redirect_to from requireAdminSession uses publicUrl from
 *        portal/src/lib/config.ts, not astro.url — so the return_to is
 *        server-constructed; we verify an attacker cannot short-circuit
 *        the step-up by crafting their own return_to)
 *   F4 — replaying a prior step-up redirect URL without completing step-up
 *        (hit the Kratos AAL2 login URL directly without a second factor;
 *        the portal /admin route must still see AAL1 on the resulting session
 *        and redirect again)
 *
 * All four sub-cases must result in a redirect to the AAL2 step-up URL
 * (aal=aal2 in Location) or a non-2xx response — never an admin page render.
 *
 * F2 two-layer check:
 *   1. Origin-less POST → Astro's built-in security.checkOrigin CSRF layer
 *      rejects forged/origin-less form POSTs with 403 before the app guard runs.
 *   2. Same-origin POST (Origin header == site origin) → passes checkOrigin and
 *      reaches requireAdminSession, which redirects to aal=aal2 step-up.
 */

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';

// ─── F1: GET /admin at AAL1 (request form) ───────────────────────────────────
test('F1 — admin at AAL1: GET /admin returns AAL2 step-up redirect', async ({
  browser,
  baseURL,
  admin,
}) => {
  // This duplicates spec D at the request layer to anchor the negative suite.
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: admin.email, password: admin.password }, baseURL);

    const resp = await ctx.request.get(`${baseURL}/admin`, { maxRedirects: 0 });
    const loc = resp.headers()['location'] ?? '';
    console.log('[F1] GET /admin AAL1 →', resp.status(), loc);

    expect(
      /aal=aal2/.test(loc),
      `F1: AAL1 admin GET /admin must redirect to aal=aal2; got ${resp.status()} ${loc}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});

// ─── F2: POST to /admin/users/new at AAL1 ───────────────────────────────────
test('F2 — admin at AAL1: POST /admin/users/new is refused (step-up redirect, no mutation)', async ({
  browser,
  baseURL,
  admin,
}) => {
  // requireAdminSession runs BEFORE any POST body is read (line 26 of new.astro:
  //   const guard = await requireAdminSession(Astro);
  //   if (guard instanceof Response) return guard;
  // so an AAL1 admin hits the guard before the CSRF check or identity creation).
  //
  // Two-layer check:
  //   Layer 1 — origin-less POST: Astro security.checkOrigin rejects with 403
  //             before requireAdminSession is reached.
  //   Layer 2 — same-origin POST: passes checkOrigin, requireAdminSession fires
  //             and redirects to the AAL2 step-up (aal=aal2 in Location).
  const origin = new URL(baseURL!).origin;
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: admin.email, password: admin.password }, baseURL);

    // Layer 1: Origin-less POST — Astro's security.checkOrigin rejects it with 403.
    const resp1 = await ctx.request.post(`${baseURL}/admin/users/new`, {
      maxRedirects: 0,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      data: 'username=attack.user&email=attack@othala.test&identityGroups=family&csrf_token=fake',
    });

    const status1 = resp1.status();
    console.log('[F2] origin-less POST /admin/users/new AAL1 →', status1);

    expect(
      status1,
      `F2 (layer 1): origin-less POST must be rejected by Astro checkOrigin with 403; got ${status1}`,
    ).toBe(403);

    // Layer 2: Same-origin POST — passes checkOrigin, reaches requireAdminSession.
    const resp2 = await ctx.request.post(`${baseURL}/admin/users/new`, {
      maxRedirects: 0,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': origin,
      },
      data: 'username=attack.user&email=attack@othala.test&identityGroups=family&csrf_token=fake',
    });

    const status2 = resp2.status();
    const loc2 = resp2.headers()['location'] ?? '';
    console.log('[F2] same-origin POST /admin/users/new AAL1 →', status2, loc2);

    // Must not return 200 (which would mean the form rendered a success state).
    expect(
      status2,
      `F2 (layer 2): POST /admin/users/new at AAL1 must not return 200; got ${status2}`,
    ).not.toBe(200);

    // The guard should redirect to the AAL2 step-up.
    expect(
      /aal=aal2/.test(loc2),
      `F2 (layer 2): AAL1 admin POST /admin/users/new must be redirected to aal=aal2; got ${status2} ${loc2}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});

// ─── F3: return_to manipulation on the step-up redirect ──────────────────────
test('F3 — return_to param on step-up URL cannot be forged to skip re-check at /admin', async ({
  browser,
  baseURL,
  admin,
}) => {
  // The step-up redirect (requireAdminSession line 80-81) is:
  //   astro.redirect(browserFlows.login({ refresh:true, aal:'aal2', returnTo: ... }))
  // where returnTo is constructed from publicUrl + astro.url.pathname — not
  // from any user-supplied input. An attacker cannot inject an arbitrary
  // return_to directly through the /admin route.
  //
  // What we test here: if an attacker manually crafts a Kratos AAL2 login URL
  // with a return_to pointing somewhere else (e.g., /admin directly) and
  // navigates there WITHOUT completing the second factor, the subsequent GET
  // /admin must STILL see AAL1 and redirect again to step-up.
  //
  // The attack:
  //   1. Login as admin at AAL1.
  //   2. Construct a forged Kratos login URL with aal=aal2 and a crafted return_to.
  //      Hit it; since no TOTP/passkey is enrolled, Kratos will return an error
  //      page or redirect to /auth/error — the admin's session remains AAL1.
  //   3. Hit /admin again. Must still redirect to aal=aal2.
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: admin.email, password: admin.password }, baseURL);

    // The attacker tries to navigate the AAL2 endpoint with a crafted return_to.
    // We don't need Kratos to succeed here; we just need to confirm that whether
    // or not the attacker tries this detour, /admin still requires AAL2.
    // Drive the forged URL (will likely 302 to an error because no TOTP enrolled).
    const forgedReturnTo = `${baseURL}/admin/users/new`;
    const forgedAal2URL =
      `${baseURL}/self-service/login/browser` +
      `?aal=aal2&refresh=true` +
      `&return_to=${encodeURIComponent(forgedReturnTo)}`;

    // Don't follow further — just probe; result is irrelevant for this assertion.
    await ctx.request.get(forgedAal2URL, { maxRedirects: 0 }).catch(() => {});

    // After the (failed) AAL2 detour, hit /admin again.
    const resp2 = await ctx.request.get(`${baseURL}/admin`, { maxRedirects: 0 });
    const loc2 = resp2.headers()['location'] ?? '';
    console.log('[F3] after forged AAL2 detour, GET /admin →', resp2.status(), loc2);

    expect(
      /aal=aal2/.test(loc2),
      `F3: /admin must still require aal=aal2 after a forged return_to detour; got ${resp2.status()} ${loc2}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});

// ─── F4: forged aal param in query string to /admin ──────────────────────────
test('F4 — supplying aal=aal2 in the /admin query string does not bypass step-up', async ({
  browser,
  baseURL,
  admin,
}) => {
  // requireAdminSession reads the AAL from session.authenticator_assurance_level
  // (the Kratos session field, portal/src/lib/admin.ts line 76), NOT from the
  // HTTP request query string. An attacker appending ?aal=aal2 to the /admin
  // URL must still be redirected to the step-up flow.
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: admin.email, password: admin.password }, baseURL);

    // Forged attempt: include aal=aal2 in the URL query.
    const resp = await ctx.request.get(`${baseURL}/admin?aal=aal2`, { maxRedirects: 0 });
    const loc = resp.headers()['location'] ?? '';
    console.log('[F4] GET /admin?aal=aal2 →', resp.status(), loc);

    // Must still redirect to a real aal=aal2 step-up via Kratos.
    expect(
      /aal=aal2/.test(loc),
      `F4: /admin?aal=aal2 must not bypass step-up; got ${resp.status()} ${loc}`,
    ).toBe(true);

    // The redirect must NOT stay on the /admin path — it must go to the Kratos
    // login flow (self-service) or the publicUrl step-up URL.
    expect(
      /\/admin/.test(loc) && !/aal=aal2/.test(loc),
      `F4: step-up redirect must not loop back to /admin without the aal=aal2 Kratos param`,
    ).toBe(false);
  } finally {
    await ctx.close();
  }
});
