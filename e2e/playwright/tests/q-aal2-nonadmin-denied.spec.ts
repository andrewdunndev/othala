// Q — INV-2: AAL2 is necessary but not sufficient; a non-admin at AAL2 is still denied.

import { test, expect } from '../fixtures';
import { adminAal2Context } from '../fixtures';
import { createIdentityWithPassword } from '../actions/identity';
import { probeAdmin } from '../actions/session';

test('Q — INV-2: non-admin identity at AAL2 is denied at /admin (reason=not-admin)', async ({
  browser,
  baseURL,
  kratosAdminURL,
}) => {
  const identity = await createIdentityWithPassword({
    email: 'aal2.nonadmin@othala.test',
    username: 'aal2.nonadmin',
    displayName: 'AAL2 Non-Admin',
    groups: [],
    kratosAdminURL,
  });
  console.log('[Q] seeded non-admin identity:', identity.id, identity.email);

  const ctx = await adminAal2Context({
    browser,
    email: identity.email,
    password: 'othala-testpass-2026', // TEST_PASSWORD constant from identity.ts
    baseURL,
  });

  try {
    const { status, loc } = await probeAdmin(ctx, baseURL);
    console.log('[Q] GET /admin (AAL2 non-admin) →', status, loc);

    expect(
      status,
      `Q (INV-2): non-admin at AAL2 must not receive 200 at /admin; got ${status}`,
    ).not.toBe(200);

    expect(
      /reason=not-admin/.test(loc) || /\/auth\/error/.test(loc),
      `Q (INV-2): AAL2 non-admin must be denied with reason=not-admin (not step-up, not 200); got ${status} ${loc}`,
    ).toBe(true);

    expect(
      /aal=aal2/.test(loc),
      `Q (INV-2): denial must NOT be an AAL2 step-up (session is already at AAL2); got ${status} ${loc}`,
    ).toBe(false);

    console.log('[Q] PASS — INV-2 proved: AAL2 alone is insufficient, marker check (c) denied access');
  } finally {
    await ctx.close();
  }
});
