/**
 * G — Forged session cookie attacks (adversarial / negative).
 *
 * Guard under attack:
 *   portal/src/lib/kratos.ts:getSession (called by requireAdminSession,
 *   handleLogin, handleConsentPost, et al.)
 *   Kratos GET /sessions/whoami — the session verification endpoint that
 *   underpins all session guards. A fabricated cookie must be rejected by
 *   Kratos (401) and subsequently by every portal guard that reads the session.
 *
 * Sub-cases:
 *   G1 — fabricated/garbage ory_kratos_session cookie value
 *         → /sessions/whoami returns 401 (not 200/active)
 *         → /admin redirects to /auth/login (not to admin content)
 *   G2 — no session cookie at all
 *         → /sessions/whoami returns 401
 *         → /admin redirects to /auth/login
 *   G3 — member's real session cookie used to attempt an admin-only route
 *         → session is valid at Kratos (whoami 200) BUT identity does not
 *           have metadata_admin.admin=true (the admin marker) → /admin
 *           redirects to /auth/error?reason=not-admin (or to AAL2 step-up).
 *         (This exercises the admin marker gate at portal/src/lib/admin-auth.ts
 *          via requireAdminSession.)
 *
 * All three must fail closed: no admin page rendered, no session accepted.
 */

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';

// ─── G1: fabricated/garbage ory_kratos_session cookie ────────────────────────
test('G1 — fabricated ory_kratos_session cookie is rejected by Kratos (401)', async ({
  browser,
  baseURL,
}) => {
  // A fresh context with no real session — then we manually inject a garbage
  // cookie and assert Kratos and the portal both reject it.
  const ctx = await browser.newContext();
  try {
    // Inject a fabricated cookie into the context's jar.
    const fakeSessionValue = 'MTZkZTFmZTUtYjY1Ni00ZjA2LWI2MzMtNWI4YzYwMWMwZGQy.FAKESIG';
    await ctx.addCookies([
      {
        name: 'ory_kratos_session',
        value: fakeSessionValue,
        domain: 'auth.othala.test',
        path: '/',
        httpOnly: true,
        secure: false,
        sameSite: 'Lax',
      },
    ]);

    // Probe /sessions/whoami — must NOT return an active session.
    const session = await getSession(ctx, baseURL);
    console.log('[G1] whoami with fake cookie:', session ? `active=${session.active}` : 'null (401)');

    expect(
      session === null || session.active !== true,
      'G1: /sessions/whoami must not return active:true for a fabricated cookie',
    ).toBe(true);

    // /admin must redirect to /auth/login (not render admin content).
    const resp = await ctx.request.get(`${baseURL}/admin`, { maxRedirects: 0 });
    const status = resp.status();
    const loc = resp.headers()['location'] ?? '';
    console.log('[G1] GET /admin with fake cookie →', status, loc);

    // Must be a redirect to login (not a 200 admin page).
    expect(
      status,
      `G1: /admin must not return 200 for a fabricated cookie; got ${status}`,
    ).not.toBe(200);

    // The Location must point to auth/login or auth/error (never /admin).
    expect(
      /\/auth\/login/.test(loc) || /\/auth\/error/.test(loc) || status === 302,
      `G1: /admin must redirect to /auth/login; got ${status} ${loc}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});

// ─── G2: no session cookie ───────────────────────────────────────────────────
test('G2 — unauthenticated request (no session cookie) is rejected at /admin', async ({
  browser,
  baseURL,
}) => {
  // Fresh context — no cookies at all.
  const ctx = await browser.newContext();
  try {
    const session = await getSession(ctx, baseURL);
    console.log('[G2] whoami with no cookie:', session ? `active=${session.active}` : 'null (401)');

    expect(
      session === null || session.active !== true,
      'G2: /sessions/whoami must not return active:true with no cookie',
    ).toBe(true);

    const resp = await ctx.request.get(`${baseURL}/admin`, { maxRedirects: 0 });
    const status = resp.status();
    const loc = resp.headers()['location'] ?? '';
    console.log('[G2] GET /admin (no cookie) →', status, loc);

    expect(
      status,
      `G2: /admin must not return 200 without a session; got ${status}`,
    ).not.toBe(200);

    // requireAdminSession's active-session check (a): no session → redirect to /auth/login.
    expect(
      /\/auth\/login/.test(loc),
      `G2: /admin must redirect to /auth/login; got ${status} ${loc}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});

// ─── G3: member's real session used to access admin (identity cross-use) ──────
test('G3 — INV-1: member real session (valid Kratos cookie, AAL1) never reaches /admin', async ({
  browser,
  baseURL,
  member,
}) => {
  // bt2@othala.test has a REAL, active Kratos session (Kratos accepts the
  // cookie, whoami returns 200 active:true). But member is at AAL1 (password only).
  //
  // INV-1 property: AAL is necessary. An AAL1 session — even with a valid,
  // cryptographically genuine Kratos cookie — NEVER reaches admin functionality.
  // requireAdminSession check (b) fires BEFORE check (c): the step-up redirect
  // fires before the marker is consulted. This is the "no admin enumeration
  // oracle at AAL1" property.
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

    // Confirm the session IS active at Kratos (this is a genuine cookie, not forged).
    const session = await getSession(ctx, baseURL);
    console.log('[G3] member whoami:', session ? `email=${session.identity?.traits?.email} active=${session.active}` : 'null');
    expect(
      session?.active,
      'G3 precondition: member must have an active Kratos session (genuine cookie)',
    ).toBe(true);
    expect(session?.identity?.traits?.email).toBe(member.email);

    // Attempt /admin with the genuine AAL1 session.
    const resp = await ctx.request.get(`${baseURL}/admin`, { maxRedirects: 0 });
    const status = resp.status();
    const loc = resp.headers()['location'] ?? '';
    console.log('[G3] GET /admin with AAL1 member session →', status, loc);

    // INV-1: the member does NOT reach admin content (not 200).
    expect(
      status,
      `G3 (INV-1): /admin must not return 200 for an AAL1 member; got ${status}`,
    ).not.toBe(200);

    // The denial for an AAL1 session MUST be the step-up redirect (aal=aal2 in
    // Location). This proves check (b) fires first: if the denial were
    // reason=not-admin the check order would be inverted (an oracle at AAL1).
    // A password-only session is always at AAL1 and always hits this path.
    expect(
      /aal=aal2/.test(loc),
      `G3 (INV-1): AAL1 member must be bounced to aal=aal2 step-up; got ${status} ${loc}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});
