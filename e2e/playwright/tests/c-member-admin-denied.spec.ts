// C — INV-1: an AAL1 session never reaches /admin; the AAL2 step-up fires before the admin-marker check (no enumeration oracle).

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';
import { probeAdmin } from '../actions/session';

test('C — INV-1: non-admin member at AAL1 never reaches /admin (step-up redirect)', async ({
  ctx,
  baseURL,
  member,
}) => {
  await loginViaJsonApi(
    ctx,
    { identifier: member.email, password: member.password },
    baseURL,
  );

  const { status, loc } = await probeAdmin(ctx, baseURL);
  console.log('[C] GET /admin with AAL1 member session →', status, loc);

  expect(
    status,
    `C (INV-1): /admin must not return 200 for an AAL1 member; got ${status}`,
  ).not.toBe(200);

  expect(
    /aal=aal2/.test(loc),
    `C (INV-1): AAL1 member must be bounced to aal=aal2 step-up (not admin content, not not-admin); got ${status} ${loc}`,
  ).toBe(true);
});
