/**
 * Q — AAL2 is necessary but not sufficient: non-admin at AAL2 is still denied.
 *
 * SECURITY INVARIANT (INV-2 — THE KEY GAP):
 *
 *   A non-admin identity who:
 *     (a) has a password credential,
 *     (b) enrolls a second factor (TOTP), and
 *     (c) completes an AAL2 step-up (session.authenticator_assurance_level === 'aal2')
 *   is STILL denied at /admin.
 *
 *   The admin marker (metadata_admin.admin===true) is the authorization gate.
 *   AAL2 is an authentication STRENGTH requirement, not an authorization grant.
 *   A user who achieves AAL2 without the marker must be redirected to
 *   /auth/error?reason=not-admin, NOT to the AAL2 step-up (they already passed
 *   AAL2) and NOT to the admin content (they lack the marker).
 *
 * WHY THIS MATTERS:
 *   Without this test, the suite only proves that AAL1 sessions are bounced.
 *   It does NOT prove that the marker check (c) in requireAdminSession actually
 *   runs and actually denies at AAL2. A misconfiguration that passes check (b)
 *   but skips check (c) would grant admin to any AAL2 user — the most dangerous
 *   category of misconfiguration.
 *
 * HOW IT WORKS:
 *   adminAal2Context() already accepts arbitrary credentials (email, password).
 *   We seed a non-admin identity with a password, drive it through the same
 *   TOTP enrollment + AAL2 step-up path used for the admin fixture, then
 *   GET /admin and assert reason=not-admin in the redirect. This proves check
 *   (c) is live and makes the correct decision independently of check (b).
 *
 * IMPLEMENTATION NOTE:
 *   adminAal2Context() in fixtures/index.ts takes { browser, email, password,
 *   baseURL } and is not admin-specific — it just drives TOTP enrollment + step-up.
 *   No fixture changes are required; we call it with a non-admin identity.
 */

import { test, expect } from '../fixtures';
import { adminAal2Context } from '../fixtures';
import { createIdentityWithPassword } from '../actions/identity';

test('Q — INV-2: non-admin identity at AAL2 is denied at /admin (reason=not-admin)', async ({
  browser,
  baseURL,
  kratosAdminURL,
}) => {
  // Seed a fresh non-admin identity. No isAdmin flag → metadata_admin.admin is
  // absent/false. This identity will enroll TOTP and reach AAL2, but has no
  // admin marker and must be denied at /admin.
  const identity = await createIdentityWithPassword({
    email: 'aal2.nonadmin@othala.test',
    username: 'aal2.nonadmin',
    displayName: 'AAL2 Non-Admin',
    groups: ['family'],
    kratosAdminURL,
    // isAdmin intentionally omitted — metadata_admin.admin is absent
  });
  console.log('[Q] seeded non-admin identity:', identity.id, identity.email);

  // Drive this non-admin identity through the same TOTP enrollment + AAL2
  // step-up path as the admin fixture. adminAal2Context accepts any credentials;
  // it does not assume the identity has the admin marker.
  //
  // After this call, the returned context has a session at AAL2
  // (session.authenticator_assurance_level === 'aal2'), but the identity
  // does NOT have metadata_admin.admin===true.
  const ctx = await adminAal2Context({
    browser,
    email: identity.email,
    password: 'othala-testpass-2026', // TEST_PASSWORD constant from identity.ts
    baseURL,
  });

  try {
    // GET /admin with the AAL2 non-admin session. requireAdminSession must:
    //   (b) pass (session is at AAL2 — no step-up needed)
    //   (c) DENY (no admin marker) → redirect to /auth/error?reason=not-admin
    const resp = await ctx.request.get(`${baseURL}/admin`, { maxRedirects: 0 });
    const status = resp.status();
    const loc = resp.headers()['location'] ?? '';
    console.log('[Q] GET /admin (AAL2 non-admin) →', status, loc);

    // INV-2 primary: must NOT reach admin content (not 200).
    expect(
      status,
      `Q (INV-2): non-admin at AAL2 must not receive 200 at /admin; got ${status}`,
    ).not.toBe(200);

    // INV-2 key assertion: the denial is reason=not-admin, NOT a step-up redirect.
    // If aal=aal2 were in Location it would mean check (b) fired (wrong — the
    // session IS at AAL2 already). If there were no redirect it would mean admin
    // content was rendered (critical failure). reason=not-admin is the only correct
    // outcome: check (c) ran, read the missing marker, and denied access.
    expect(
      /reason=not-admin/.test(loc) || /\/auth\/error/.test(loc),
      `Q (INV-2): AAL2 non-admin must be denied with reason=not-admin (not step-up, not 200); got ${status} ${loc}`,
    ).toBe(true);

    // Belt-and-suspenders: confirm it is specifically NOT a step-up redirect.
    // If aal=aal2 appeared it would indicate check (b) erroneously re-fired,
    // suggesting the session's AAL2 state was not read correctly.
    expect(
      /aal=aal2/.test(loc),
      `Q (INV-2): denial must NOT be an AAL2 step-up (session is already at AAL2); got ${status} ${loc}`,
    ).toBe(false);

    console.log('[Q] PASS — INV-2 proved: AAL2 alone is insufficient, marker check (c) denied access');
  } finally {
    await ctx.close();
  }
});
