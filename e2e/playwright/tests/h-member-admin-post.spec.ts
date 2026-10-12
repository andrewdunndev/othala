// H — INV-1: a non-admin AAL1 session cannot POST to any /admin mutation endpoint.

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';

const DUMMY_FORM_BODY =
  'action=save&username=attack.user&email=attack%40othala.test' +
  '&identityGroups=grafana-access&csrf_token=garbage-token';

const FAKE_UUID = '00000000-0000-4000-a000-000000000001';

const CROSS_SITE_FORM_HEADERS = {
  'Content-Type': 'application/x-www-form-urlencoded',
  'Origin': 'https://attacker.example',
  'Sec-Fetch-Site': 'cross-site',
};

test('H1 — INV-1: member POST /admin/users/new at AAL1 is denied (step-up redirect, not 200)', async ({
  ctx,
  baseURL,
  member,
}) => {
  const origin = new URL(baseURL!).origin;
  await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

  const session = await getSession(ctx, baseURL);
  expect(session?.active, 'H1 precondition: member must have active session').toBe(true);

  const resp1 = await ctx.request.post(`${baseURL}/admin/users/new`, {
    maxRedirects: 0,
    headers: CROSS_SITE_FORM_HEADERS,
    data: DUMMY_FORM_BODY,
  });

  const status1 = resp1.status();
  console.log('[H1] cross-site POST /admin/users/new →', status1);

  expect(
    status1,
    `H1 (layer 1): cross-site POST must be rejected by Astro checkOrigin with 403; got ${status1}`,
  ).toBe(403);

  const respNoOrigin = await ctx.request.post(`${baseURL}/admin/users/new`, {
    maxRedirects: 0,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    data: DUMMY_FORM_BODY,
  });

  const statusNoOrigin = respNoOrigin.status();
  const locNoOrigin = respNoOrigin.headers()['location'] ?? '';
  console.log('[H1] origin-less POST /admin/users/new →', statusNoOrigin, locNoOrigin);

  expect(
    /aal=aal2/.test(locNoOrigin),
    `H1 (INV-1): origin-less AAL1 member POST must redirect to aal=aal2 step-up; got ${statusNoOrigin} ${locNoOrigin}`,
  ).toBe(true);

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

  expect(
    status2,
    `H1 (INV-1): member POST /admin/users/new must not return 200; got ${status2}`,
  ).not.toBe(200);

  expect(
    /aal=aal2/.test(loc2),
    `H1 (INV-1): AAL1 member POST must redirect to aal=aal2 step-up (not 200, not 403); got ${status2} ${loc2}`,
  ).toBe(true);
});

test('H2 — INV-1: member POST /admin/users/<own-id> at AAL1 is denied (step-up redirect, not CSRF)', async ({
  ctx,
  baseURL,
  member,
}) => {
  const origin = new URL(baseURL!).origin;
  await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

  const session = await getSession(ctx, baseURL);
  expect(session?.active, 'H2 precondition: member must have active session').toBe(true);
  const ownId = session?.identity?.id ?? FAKE_UUID;
  console.log('[H2] member identity id:', ownId);

  const resp1 = await ctx.request.post(`${baseURL}/admin/users/${ownId}`, {
    maxRedirects: 0,
    headers: CROSS_SITE_FORM_HEADERS,
    data: DUMMY_FORM_BODY,
  });

  const status1 = resp1.status();
  console.log('[H2] cross-site POST /admin/users/<own-id> →', status1);

  expect(
    status1,
    `H2 (layer 1): cross-site POST must be rejected by Astro checkOrigin with 403; got ${status1}`,
  ).toBe(403);

  const respNoOrigin = await ctx.request.post(`${baseURL}/admin/users/${ownId}`, {
    maxRedirects: 0,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    data: DUMMY_FORM_BODY,
  });

  const statusNoOrigin = respNoOrigin.status();
  const locNoOrigin = respNoOrigin.headers()['location'] ?? '';
  console.log('[H2] origin-less POST /admin/users/<own-id> →', statusNoOrigin, locNoOrigin);

  expect(
    /aal=aal2/.test(locNoOrigin),
    `H2 (INV-1): origin-less AAL1 member POST own-id must redirect to aal=aal2 step-up; got ${statusNoOrigin} ${locNoOrigin}`,
  ).toBe(true);

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
    `H2 (INV-1): member POST own-id must not return 200; got ${status2}`,
  ).not.toBe(200);

  expect(
    /aal=aal2/.test(loc2),
    `H2 (INV-1): AAL1 member POST own-id must redirect to aal=aal2 step-up (not 200, not 403); got ${status2} ${loc2}`,
  ).toBe(true);
});

test('H3 — layer 1: member POST with mismatched Origin and no Sec-Fetch-Site is rejected by checkOrigin', async ({
  ctx,
  baseURL,
  member,
}) => {
  await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

  const resp = await ctx.request.post(`${baseURL}/admin/users/new`, {
    maxRedirects: 0,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Origin': 'https://attacker.example',
    },
    data: DUMMY_FORM_BODY,
  });

  expect(
    resp.status(),
    `H3 (layer 1): Origin mismatch without Sec-Fetch-Site must be rejected with 403; got ${resp.status()}`,
  ).toBe(403);
});
