/**
 * H — Non-admin member POSTs to /admin mutation endpoints (INV-1: AAL is necessary).
 *
 * SECURITY INVARIANT (INV-1): An AAL1 session NEVER reaches admin mutation
 * functionality. requireAdminSession enforces checks IN ORDER:
 *   (a) active session — yes (member has AAL1 password session)
 *   (b) AAL2: aal !== 'aal2' → step-up redirect fires FIRST
 *   (c) admin marker: never reached for an AAL1 session
 *
 * Spec C (c-member-admin-denied.spec.ts) covers GET /admin. This spec covers
 * POST (mutation) verbs. INV-1 must hold for mutations too: a non-admin member
 * with a real AAL1 Kratos session must be denied on every mutation.
 *
 * Endpoints targeted:
 *   H1 — POST /admin/users/new (create-user mutation)
 *   H2 — POST /admin/users/<member-own-id> (self-edit attempt via mutation verb)
 *   H3 — POST /admin/users/<fake-uuid> (blind mutation on unknown user)
 *
 * Two-layer check per POST test:
 *   Layer 1 (origin-less): Astro's security.checkOrigin rejects it with 403
 *     before requireAdminSession runs.
 *   Layer 2 (same-origin): passes checkOrigin, reaches requireAdminSession.
 *     For an AAL1 member the denial is the step-up redirect (aal=aal2 in Location).
 *     This is NOT a 403 — the redirect confirms requireAdminSession fired BEFORE
 *     any CSRF or body processing (right guard, right order).
 */

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';

/** Minimal form body for the POST — fields don't matter because requireAdminSession
 *  fires before any body is read; the body just satisfies HTTP POST semantics. */
const DUMMY_FORM_BODY =
  'action=save&username=attack.user&email=attack%40othala.test' +
  '&identityGroups=grafana-access&csrf_token=garbage-token';

/** A plausible but non-existent UUID (the [id] route param). */
const FAKE_UUID = '00000000-0000-4000-a000-000000000001';

// ─── H1: POST /admin/users/new as non-admin member ───────────────────────────
test('H1 — INV-1: member POST /admin/users/new at AAL1 is denied (step-up redirect, not 200)', async ({
  browser,
  baseURL,
  member,
}) => {
  const origin = new URL(baseURL!).origin;
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

    // Confirm the session is active (non-admin member, AAL1 real session).
    const session = await getSession(ctx, baseURL);
    expect(session?.active, 'H1 precondition: member must have active session').toBe(true);

    // Layer 1: Origin-less POST — Astro's security.checkOrigin rejects it with 403
    // before requireAdminSession ever runs.
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
    // INV-1: an AAL1 member must be denied. The denial is NOT a 200 (no mutation
    // fires) and NOT a 403 (requireAdminSession redirects, not CSRF-rejects). The
    // step-up redirect (aal=aal2 in Location) is the expected denial signal,
    // proving requireAdminSession fired in the right order before any body read.
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

    // INV-1: must not return 200 (no form render, no user created).
    expect(
      status2,
      `H1 (INV-1): member POST /admin/users/new must not return 200; got ${status2}`,
    ).not.toBe(200);

    // The denial for an AAL1 session is the step-up redirect (aal=aal2). This
    // confirms requireAdminSession check (b) fired before any body or marker
    // processing — a 403 here would indicate the wrong guard (CSRF, not admin gate).
    expect(
      /aal=aal2/.test(loc2),
      `H1 (INV-1): AAL1 member POST must redirect to aal=aal2 step-up (not 200, not 403); got ${status2} ${loc2}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});

// ─── H2: POST /admin/users/<member-own-id> (self-edit attempt) ───────────────
test('H2 — INV-1: member POST /admin/users/<own-id> at AAL1 is denied (step-up redirect, not CSRF)', async ({
  browser,
  baseURL,
  member,
}) => {
  // Even if the member knows their own identity id (visible via /sessions/whoami),
  // requireAdminSession fires BEFORE any id-based lookup or body processing.
  // INV-1: the AAL1 step-up fires regardless of the id in the path.
  const origin = new URL(baseURL!).origin;
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

    const session = await getSession(ctx, baseURL);
    expect(session?.active, 'H2 precondition: member must have active session').toBe(true);
    const ownId = session?.identity?.id ?? FAKE_UUID;
    console.log('[H2] member identity id:', ownId);

    // Layer 1: Origin-less POST — Astro's security.checkOrigin rejects with 403.
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
    // INV-1: must be a redirect (not 200, not 403). A 403 here would mean the CSRF
    // check fired INSTEAD of the admin guard — the wrong guard, wrong order.
    // A step-up redirect (aal=aal2) confirms requireAdminSession check (b) fired
    // first, before any id-lookup or body read.
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

    // INV-1: member must not reach /admin mutation content.
    expect(
      status2,
      `H2 (INV-1): member POST own-id must not return 200; got ${status2}`,
    ).not.toBe(200);

    // The denial for an AAL1 session MUST be the step-up redirect (aal=aal2),
    // not a 403. This proves guard order: requireAdminSession (b) fired before
    // any CSRF or identity-id lookup.
    expect(
      /aal=aal2/.test(loc2),
      `H2 (INV-1): AAL1 member POST own-id must redirect to aal=aal2 step-up (not 200, not 403); got ${status2} ${loc2}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});

// ─── H3: POST /admin/users/<fake-uuid> (blind mutation) ──────────────────────
test('H3 — INV-1: member POST /admin/users/<unknown-uuid> at AAL1 is denied (step-up redirect)', async ({
  browser,
  baseURL,
  member,
}) => {
  // INV-1: the guard is not id-dependent. An attacker who guesses a valid UUID
  // is still denied: requireAdminSession fires before any id lookup.
  const origin = new URL(baseURL!).origin;
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

    const session = await getSession(ctx, baseURL);
    expect(session?.active, 'H3 precondition: member must have active session').toBe(true);

    // Layer 1: Origin-less POST — Astro's security.checkOrigin rejects with 403.
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
    // INV-1: the guard fires before any id lookup. The step-up redirect (aal=aal2)
    // proves the admin gate fired in the right order regardless of the path id.
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

    // INV-1: must not return 200 regardless of the id in the path.
    expect(
      status2,
      `H3 (INV-1): member POST /admin/users/<fake-uuid> must not return 200; got ${status2}`,
    ).not.toBe(200);

    // The denial must be the step-up redirect (aal=aal2), confirming requireAdminSession
    // check (b) fired before any id-based lookup — the guard is not id-gated.
    expect(
      /aal=aal2/.test(loc2),
      `H3 (INV-1): AAL1 member POST unknown-id must redirect to aal=aal2 step-up; got ${status2} ${loc2}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});
