// F — AAL2 bypass attempts against /admin never reach admin content.

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';

test('F2 — admin at AAL1: POST /admin/users/new is refused (step-up redirect, no mutation)', async ({
  ctx,
  baseURL,
  admin,
}) => {
  const origin = new URL(baseURL!).origin;
  await loginViaJsonApi(ctx, { identifier: admin.email, password: admin.password }, baseURL);

  const body = 'username=attack.user&email=attack@othala.test&identityGroups=grafana-access&csrf_token=fake';

  const resp1 = await ctx.request.post(`${baseURL}/admin/users/new`, {
    maxRedirects: 0,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Origin': 'https://attacker.example',
      'Sec-Fetch-Site': 'cross-site',
    },
    data: body,
  });

  const status1 = resp1.status();
  console.log('[F2] cross-site POST /admin/users/new AAL1 →', status1);

  expect(
    status1,
    `F2 (layer 1): cross-site POST must be rejected by Astro checkOrigin with 403; got ${status1}`,
  ).toBe(403);

  const respNoOrigin = await ctx.request.post(`${baseURL}/admin/users/new`, {
    maxRedirects: 0,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    data: body,
  });

  const statusNoOrigin = respNoOrigin.status();
  const locNoOrigin = respNoOrigin.headers()['location'] ?? '';
  console.log('[F2] origin-less POST /admin/users/new AAL1 →', statusNoOrigin, locNoOrigin);

  expect(
    /aal=aal2/.test(locNoOrigin),
    `F2 (layer 2): origin-less AAL1 admin POST must be redirected to aal=aal2; got ${statusNoOrigin} ${locNoOrigin}`,
  ).toBe(true);

  const resp2 = await ctx.request.post(`${baseURL}/admin/users/new`, {
    maxRedirects: 0,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Origin': origin,
    },
    data: body,
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
    `F4: /admin?aal=aal2 must not bypass step-up; got ${resp.status()} ${loc}`,
  ).toBe(true);
});

test('F3 — layer 1: mismatched Origin without Sec-Fetch-Site is rejected by checkOrigin', async ({
  ctx,
  baseURL,
  admin,
}) => {
  await loginViaJsonApi(ctx, { identifier: admin.email, password: admin.password }, baseURL);

  const resp = await ctx.request.post(`${baseURL}/admin/users/new`, {
    maxRedirects: 0,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Origin': 'https://attacker.example',
    },
    data: 'username=attack.user&email=attack@othala.test&identityGroups=grafana-access&csrf_token=fake',
  });

  expect(
    resp.status(),
    `F3 (layer 1): Origin mismatch without Sec-Fetch-Site must be rejected with 403; got ${resp.status()}`,
  ).toBe(403);
});
