/**
 * H — Non-admin member POSTs to /admin mutation endpoints (adversarial / negative).
 *
 * Guard under attack:
 *   portal/src/lib/admin.ts:requireAdminSession
 *   — specifically the allowlist check:
 *       if (!isAdminId(session.identity.id)) return redirect('/auth/error?reason=not-admin')
 *   — and the AAL2 check that follows it.
 *
 * Spec C (c-member-admin-denied.spec.ts) only covers a browser GET navigation
 * to /admin. This spec covers POST (mutation) verbs against real admin mutation
 * endpoints in the portal.  A non-admin member with a real, active Kratos
 * session must be denied on every mutation, not just on navigation.
 *
 * Endpoints targeted:
 *   H1 — POST /admin/users/new (create-user mutation)
 *         portal/src/pages/admin/users/new.astro line 26:
 *           requireAdminSession runs at SSR entry, before any POST body read.
 *   H2 — POST /admin/users/<member-own-id>  (self-edit attempt via mutation verb)
 *         portal/src/pages/admin/users/[id].astro line 43:
 *           requireAdminSession runs first; even if member knows their own
 *           identity id, the allowlist gate must fire before the CSRF check
 *           or any Kratos write.
 *   H3 — POST /admin/users/<fake-uuid>  (blind mutation on unknown user)
 *         Same guard, different id — ensures the gate is not id-dependent.
 *
 * Two-layer check per POST test:
 *   1. Origin-less POST → Astro's built-in security.checkOrigin CSRF layer
 *      rejects forged/origin-less form POSTs with 403 before the app guard runs.
 *   2. Same-origin POST (Origin header == site origin) → passes checkOrigin and
 *      reaches the app guard (requireAdminSession → 302 reason=not-admin).
 *
 * All three must be denied (redirect to /auth/error?reason=not-admin or
 * equivalent) — never a 200, never a side effect.
 */

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';

/** Minimal form body for the POST — fields don't matter because requireAdminSession
 *  fires before any body is read; the body just satisfies HTTP POST semantics. */
const DUMMY_FORM_BODY =
  'action=save&username=attack.user&email=attack%40othala.test' +
  '&identityGroups=family&csrf_token=garbage-token';

/** A plausible but non-existent UUID (the [id] route param). */
const FAKE_UUID = '00000000-0000-4000-a000-000000000001';

// ─── H1: POST /admin/users/new as non-admin member ───────────────────────────
test('H1 — member POST /admin/users/new is denied (reason=not-admin)', async ({
  browser,
  baseURL,
  member,
}) => {
  const origin = new URL(baseURL!).origin;
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

    // Confirm the session is active (non-admin member, real session).
    const session = await getSession(ctx, baseURL);
    expect(session?.active, 'H1 precondition: member must have active session').toBe(true);

    // Layer 1: Origin-less POST — Astro's security.checkOrigin rejects it with 403
    // before the app guard ever runs.
    const resp1 = await ctx.request.post(`${baseURL}/admin/users/new`, {
      maxRedirects: 0,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      data: DUMMY_FORM_BODY,
    });

    const status1 = resp1.status();
    console.log('[H1] origin-less POST /admin/users/new →', status1);

    expect(
      status1,
      `H1 (layer 1): origin-less POST must be rejected by Astro checkOrigin with 403; got ${status1}`,
    ).toBe(403);

    // Layer 2: Same-origin POST — passes checkOrigin, reaches requireAdminSession.
    // Must redirect to not-admin error, never return 200.
    const resp2 = await ctx.request.post(`${baseURL}/admin/users/new`, {
      maxRedirects: 0,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': origin,
      },
      data: DUMMY_FORM_BODY,
    });

    const status2 = resp2.status();
    const loc2 = resp2.headers()['location'] ?? '';
    console.log('[H1] same-origin POST /admin/users/new →', status2, loc2);

    // Must not return 200 (no form render, no user created).
    expect(
      status2,
      `H1 (layer 2): member POST /admin/users/new must not return 200; got ${status2}`,
    ).not.toBe(200);

    // Must redirect to the not-admin error.
    expect(
      /reason=not-admin/.test(loc2) || /\/auth\/error/.test(loc2),
      `H1 (layer 2): member must be denied at /admin/users/new with reason=not-admin; got ${status2} ${loc2}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});

// ─── H2: POST /admin/users/<member-own-id> (self-edit attempt) ───────────────
test('H2 — member POST /admin/users/<own-id> is denied (reason=not-admin, not CSRF)', async ({
  browser,
  baseURL,
  member,
}) => {
  // Even if the member knows their own identity id (it is their subject, visible
  // e.g. via /sessions/whoami), the allowlist guard fires BEFORE any id-based
  // lookup or CSRF verification.
  const origin = new URL(baseURL!).origin;
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

    const session = await getSession(ctx, baseURL);
    expect(session?.active, 'H2 precondition: member must have active session').toBe(true);
    const ownId = session?.identity?.id ?? FAKE_UUID;
    console.log('[H2] member identity id:', ownId);

    // Layer 1: Origin-less POST — Astro's security.checkOrigin rejects it with 403.
    const resp1 = await ctx.request.post(`${baseURL}/admin/users/${ownId}`, {
      maxRedirects: 0,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      data: DUMMY_FORM_BODY,
    });

    const status1 = resp1.status();
    console.log('[H2] origin-less POST /admin/users/<own-id> →', status1);

    expect(
      status1,
      `H2 (layer 1): origin-less POST must be rejected by Astro checkOrigin with 403; got ${status1}`,
    ).toBe(403);

    // Layer 2: Same-origin POST — passes checkOrigin, reaches requireAdminSession.
    const resp2 = await ctx.request.post(`${baseURL}/admin/users/${ownId}`, {
      maxRedirects: 0,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': origin,
      },
      data: DUMMY_FORM_BODY,
    });

    const status2 = resp2.status();
    const loc2 = resp2.headers()['location'] ?? '';
    console.log('[H2] same-origin POST /admin/users/<own-id> →', status2, loc2);

    expect(
      status2,
      `H2 (layer 2): member POST own-id must not return 200; got ${status2}`,
    ).not.toBe(200);

    // Guard: requireAdminSession → not-admin redirect. Must NOT fall through to
    // CSRF check (which would return 403 "CSRF: ..." — a different response code
    // that would signal the guard fired in the wrong order).
    expect(
      /reason=not-admin/.test(loc2) || /\/auth\/error/.test(loc2),
      `H2 (layer 2): member must be denied with reason=not-admin (not CSRF error); got ${status2} ${loc2}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});

// ─── H3: POST /admin/users/<fake-uuid> (blind mutation) ──────────────────────
test('H3 — member POST /admin/users/<unknown-uuid> is denied (reason=not-admin)', async ({
  browser,
  baseURL,
  member,
}) => {
  const origin = new URL(baseURL!).origin;
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

    const session = await getSession(ctx, baseURL);
    expect(session?.active, 'H3 precondition: member must have active session').toBe(true);

    // Layer 1: Origin-less POST — Astro's security.checkOrigin rejects it with 403.
    const resp1 = await ctx.request.post(`${baseURL}/admin/users/${FAKE_UUID}`, {
      maxRedirects: 0,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      data: DUMMY_FORM_BODY,
    });

    const status1 = resp1.status();
    console.log('[H3] origin-less POST /admin/users/<fake-uuid> →', status1);

    expect(
      status1,
      `H3 (layer 1): origin-less POST must be rejected by Astro checkOrigin with 403; got ${status1}`,
    ).toBe(403);

    // Layer 2: Same-origin POST — passes checkOrigin, reaches requireAdminSession.
    const resp2 = await ctx.request.post(`${baseURL}/admin/users/${FAKE_UUID}`, {
      maxRedirects: 0,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': origin,
      },
      data: DUMMY_FORM_BODY,
    });

    const status2 = resp2.status();
    const loc2 = resp2.headers()['location'] ?? '';
    console.log('[H3] same-origin POST /admin/users/<fake-uuid> →', status2, loc2);

    expect(
      status2,
      `H3 (layer 2): member POST /admin/users/<fake-uuid> must not return 200; got ${status2}`,
    ).not.toBe(200);

    expect(
      /reason=not-admin/.test(loc2) || /\/auth\/error/.test(loc2),
      `H3 (layer 2): member must be denied with reason=not-admin on unknown-id; got ${status2} ${loc2}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});
