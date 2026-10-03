// G — forged or malformed session cookies never authenticate.

import { test, expect } from '../fixtures';
import { getSession, probeAdmin } from '../actions/session';

test('G1 — fabricated ory_kratos_session cookie is rejected by Kratos (401)', async ({
  ctx,
  baseURL,
}) => {
  const fakeSessionValue = 'MTZkZTFmZTUtYjY1Ni00ZjA2LWI2MzMtNWI4YzYwMWMwZGQy.FAKESIG';
  await ctx.addCookies([
    {
      name: 'ory_kratos_session',
      value: fakeSessionValue,
      domain: 'auth.othala.test',
      path: '/',
      httpOnly: true,
      secure: false,
      sameSite: 'Lax',
    },
  ]);

  const session = await getSession(ctx, baseURL);
  console.log('[G1] whoami with fake cookie:', session ? `active=${session.active}` : 'null (401)');

  expect(
    session === null || session.active !== true,
    'G1: /sessions/whoami must not return active:true for a fabricated cookie',
  ).toBe(true);

  const { status, loc } = await probeAdmin(ctx, baseURL);
  console.log('[G1] GET /admin with fake cookie →', status, loc);

  expect(
    status,
    `G1: /admin must not return 200 for a fabricated cookie; got ${status}`,
  ).not.toBe(200);

  expect(
    /\/auth\/login/.test(loc) || /\/auth\/error/.test(loc) || status === 302,
    `G1: /admin must redirect to /auth/login; got ${status} ${loc}`,
  ).toBe(true);
});

test('G2 — unauthenticated request (no session cookie) is rejected at /admin', async ({
  ctx,
  baseURL,
}) => {
  const session = await getSession(ctx, baseURL);
  console.log('[G2] whoami with no cookie:', session ? `active=${session.active}` : 'null (401)');

  expect(
    session === null || session.active !== true,
    'G2: /sessions/whoami must not return active:true with no cookie',
  ).toBe(true);

  const { status, loc } = await probeAdmin(ctx, baseURL);
  console.log('[G2] GET /admin (no cookie) →', status, loc);

  expect(
    status,
    `G2: /admin must not return 200 without a session; got ${status}`,
  ).not.toBe(200);

  expect(
    /\/auth\/login/.test(loc),
    `G2: /admin must redirect to /auth/login; got ${status} ${loc}`,
  ).toBe(true);
});
