// F — AAL2 bypass attempts against /admin never reach admin content.

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';
import { probeAdmin } from '../actions/session';

test('F1 — admin at AAL1: GET /admin returns AAL2 step-up redirect', async ({
  ctx,
  baseURL,
  admin,
}) => {
  await loginViaJsonApi(ctx, { identifier: admin.email, password: admin.password }, baseURL);

  const { status, loc } = await probeAdmin(ctx, baseURL);
  console.log('[F1] GET /admin AAL1 →', status, loc);

  expect(
    /aal=aal2/.test(loc),
    `F1: AAL1 admin GET /admin must redirect to aal=aal2; got ${status} ${loc}`,
  ).toBe(true);
});

test('F2 — admin at AAL1: POST /admin/users/new is refused (step-up redirect, no mutation)', async ({
  ctx,
  baseURL,
  admin,
}) => {
  const origin = new URL(baseURL!).origin;
  await loginViaJsonApi(ctx, { identifier: admin.email, password: admin.password }, baseURL);

  const resp1 = await ctx.request.post(`${baseURL}/admin/users/new`, {
    maxRedirects: 0,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    data: 'username=attack.user&email=attack@othala.test&identityGroups=grafana-access&csrf_token=fake',
  });

  const status1 = resp1.status();
  console.log('[F2] origin-less POST /admin/users/new AAL1 →', status1);

  expect(
    status1,
    `F2 (layer 1): origin-less POST must be rejected by Astro checkOrigin with 403; got ${status1}`,
  ).toBe(403);

  const resp2 = await ctx.request.post(`${baseURL}/admin/users/new`, {
    maxRedirects: 0,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Origin': origin,
    },
    data: 'username=attack.user&email=attack@othala.test&identityGroups=grafana-access&csrf_token=fake',
  });

  const status2 = resp2.status();
  const loc2 = resp2.headers()['location'] ?? '';
  console.log('[F2] same-origin POST /admin/users/new AAL1 →', status2, loc2);

  expect(
    status2,
    `F2 (layer 2): POST /admin/users/new at AAL1 must not return 200; got ${status2}`,
  ).not.toBe(200);

  expect(
    /aal=aal2/.test(loc2),
    `F2 (layer 2): AAL1 admin POST /admin/users/new must be redirected to aal=aal2; got ${status2} ${loc2}`,
  ).toBe(true);
});

test('F3 — return_to param on step-up URL cannot be forged to skip re-check at /admin', async ({
  baseURL,
  admin,
  ctx,
}) => {
  await loginViaJsonApi(ctx, { identifier: admin.email, password: admin.password }, baseURL);

  const forgedReturnTo = `${baseURL}/admin/users/new`;
  const forgedAal2URL =
    `${baseURL}/self-service/login/browser` +
    `?aal=aal2&refresh=true` +
    `&return_to=${encodeURIComponent(forgedReturnTo)}`;

  await ctx.request.get(forgedAal2URL, { maxRedirects: 0 }).catch(() => {});

  const resp2 = await ctx.request.get(`${baseURL}/admin`, { maxRedirects: 0 });
  const loc2 = resp2.headers()['location'] ?? '';
  console.log('[F3] after forged AAL2 detour, GET /admin →', resp2.status(), loc2);

  expect(
    /aal=aal2/.test(loc2),
    `F3: /admin must still require aal=aal2 after a forged return_to detour; got ${resp2.status()} ${loc2}`,
  ).toBe(true);
});

test('F4 — supplying aal=aal2 in the /admin query string does not bypass step-up', async ({
  ctx,
  baseURL,
  admin,
}) => {
  await loginViaJsonApi(ctx, { identifier: admin.email, password: admin.password }, baseURL);

  const resp = await ctx.request.get(`${baseURL}/admin?aal=aal2`, { maxRedirects: 0 });
  const loc = resp.headers()['location'] ?? '';
  console.log('[F4] GET /admin?aal=aal2 →', resp.status(), loc);

  expect(
    /aal=aal2/.test(loc),
    `F4: /admin?aal=aal2 must not bypass step-up; got ${status} ${loc}`,
  ).toBe(true);

  expect(
    /\/admin/.test(loc) && !/aal=aal2/.test(loc),
    `F4: step-up redirect must not loop back to /admin without the aal=aal2 Kratos param`,
  ).toBe(false);
});
