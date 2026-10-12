// D — INV-1/INV-3: an admin at AAL1 is stepped up to the configured origin; an admin at AAL2 reaches /admin.

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';
import { adminAal2Context } from '../fixtures';
import { probeAdmin } from '../actions/session';

test('D1 — INV-1: admin at AAL1 is redirected to AAL2 step-up (marker alone insufficient)', async ({
  ctx,
  baseURL,
  admin,
}) => {
  await loginViaJsonApi(
    ctx,
    { identifier: admin.email, password: admin.password },
    baseURL,
  );

  const { status, loc } = await probeAdmin(ctx, baseURL);
  console.log('[D1] /admin (AAL1 admin) →', status, loc);

  expect(
    /aal=aal2/.test(loc),
    `D1 (INV-1): admin at AAL1 must be redirected to AAL2 step-up; got ${status} ${loc}`,
  ).toBe(true);

  const expectedOrigin = new URL(String(baseURL)).origin;
  expect(
    new URL(loc, baseURL).searchParams.get('return_to'),
    'D1: step-up return_to is the requested path, encoded once',
  ).toBe('/admin');

  expect(
    /^https?:\/\//.test(loc) ? new URL(loc).origin : expectedOrigin,
    `D1 (portability): step-up must stay on the configured origin; got ${loc}`,
  ).toBe(expectedOrigin);
});

test('D2 — INV-3: admin at AAL2 reaches /admin (marker GRANTS, gate is not always-deny)', async ({
  browser,
  baseURL,
  admin,
}) => {
  const ctx = await adminAal2Context({
    browser,
    email: admin.email,
    password: admin.password,
    baseURL,
  });

  try {
    const resp = await ctx.request.get(`${baseURL}/admin`, { maxRedirects: 10 });
    const status = resp.status();
    const finalUrl = resp.url();
    console.log('[D2] GET /admin (AAL2 admin) →', status, finalUrl);

    expect(
      status,
      `D2 (INV-3): admin at AAL2 must receive 200 at /admin; got ${status} (url: ${finalUrl})`,
    ).toBe(200);

    expect(new URL(finalUrl).pathname, 'D2 (INV-3): /admin lands on the People page, not a step-up').toBe('/admin/users');
    expect(await resp.text(), 'D2 (INV-3): the admin People heading').toMatch(/<h1[^>]*>People\b/);
  } finally {
    await ctx.close();
  }
});
