// G — forged or malformed session cookies never authenticate.

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';
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

test('G3 — INV-1: member real session (valid Kratos cookie, AAL1) never reaches /admin', async ({
  ctx,
  baseURL,
  member,
}) => {
  await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

  const session = await getSession(ctx, baseURL);
  console.log('[G3] member whoami:', session ? `email=${session.identity?.traits?.email} active=${session.active}` : 'null');
  expect(
    session?.active,
    'G3 precondition: member must have an active Kratos session (genuine cookie)',
  ).toBe(true);
  expect(session?.identity?.traits?.email).toBe(member.email);

  const { status, loc } = await probeAdmin(ctx, baseURL);
  console.log('[G3] GET /admin with AAL1 member session →', status, loc);

  expect(
    status,
    `G3 (INV-1): /admin must not return 200 for an AAL1 member; got ${status}`,
  ).not.toBe(200);

  expect(
    /aal=aal2/.test(loc),
    `G3 (INV-1): AAL1 member must be bounced to aal=aal2 step-up; got ${status} ${loc}`,
  ).toBe(true);
});
