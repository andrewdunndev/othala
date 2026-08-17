/**
 * C — Non-admin member denied at /admin (INV-1: AAL is necessary).
 *
 * SECURITY INVARIANT (INV-1): An AAL1 session — regardless of identity — NEVER
 * reaches admin functionality. requireAdminSession enforces the SP-3 trinity
 * in strict order:
 *   (a) active session — yes (member has an AAL1 password session)
 *   (b) AAL2 server-side — NO → the step-up redirect fires FIRST; the admin
 *       marker check (c) is never reached for an AAL1 session.
 *   (c) admin marker — not evaluated (the gate already fired at (b))
 *
 * This is the "no admin-enumeration oracle at AAL1" property: an attacker
 * cannot learn whether an identity has the admin marker by probing /admin at AAL1,
 * because the step-up fires unconditionally before the marker is ever read.
 *
 * The denial signal is the AAL2 step-up redirect: a non-admin member has no
 * second factor enrolled and cannot satisfy AAL2.
 */

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';

test('C — INV-1: non-admin member at AAL1 never reaches /admin (step-up redirect)', async ({
  browser,
  baseURL,
  member,
}) => {
  const ctx = await browser.newContext();

  try {
    // Login as member (AAL1 password session, no admin marker, no second factor).
    await loginViaJsonApi(
      ctx,
      { identifier: member.email, password: member.password },
      baseURL,
    );

    // Capture the first 30x from /admin without following it. requireAdminSession
    // fires before any page content is rendered: check (b) AAL2 fires first.
    const resp = await ctx.request.get(`${baseURL}/admin`, { maxRedirects: 0 });
    const status = resp.status();
    const loc = resp.headers()['location'] ?? '';
    console.log('[C] GET /admin with AAL1 member session →', status, loc);

    // INV-1 primary assertion: the member does NOT reach /admin (not 200).
    // The denial is the AAL2 step-up redirect — the gate fires at (b) BEFORE (c),
    // so even a non-admin never sees admin content and cannot probe the marker.
    expect(
      status,
      `C (INV-1): /admin must not return 200 for an AAL1 member; got ${status}`,
    ).not.toBe(200);

    // The denial mechanism for an AAL1 session MUST be the step-up redirect
    // (aal=aal2 in Location). This is what proves (b) fires before (c): if the
    // denial were reason=not-admin the gate order would be inverted (an oracle leak).
    // An AAL1 password-only session always lands here.
    expect(
      /aal=aal2/.test(loc),
      `C (INV-1): AAL1 member must be bounced to aal=aal2 step-up (not admin content, not not-admin); got ${status} ${loc}`,
    ).toBe(true);
  } finally {
    await ctx.close();
  }
});
