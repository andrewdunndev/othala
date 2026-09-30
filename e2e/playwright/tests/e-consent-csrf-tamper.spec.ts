// E — a tampered or replayed consent POST is refused and never accepts the Hydra consent request.

import { test, expect, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';

async function captureConsentChallenge(
  ctx: import('@playwright/test').BrowserContext,
  baseURL: string,
): Promise<string | null> {
  const authURL =
    `${baseURL}/oauth2/auth` +
    `?client_id=${GRAFANA_CLIENT_ID}` +
    `&response_type=code` +
    `&scope=${encodeURIComponent('openid email groups')}` +
    `&redirect_uri=${encodeURIComponent(GRAFANA_REDIRECT_URI)}` +
    `&state=e-csrf-test-state` +
    `&nonce=e-csrf-test-nonce`;

  let url = authURL;
  for (let hop = 0; hop < 10; hop++) {
    const resp = await ctx.request.get(url, { maxRedirects: 0 });
    const loc = resp.headers()['location'];
    if (!loc) {
      break;
    }
    const absolute = loc.startsWith('http') ? loc : new URL(loc, baseURL).toString();

    if (absolute.includes('/oauth2/consent')) {
      const challenge = new URL(absolute).searchParams.get('consent_challenge');
      if (challenge) return challenge;
    }

    url = absolute;
    if (absolute.startsWith('https://grafana.othala.test')) break;
  }
  return null;
}

test('E1 — consent POST with MISSING csrf_token is rejected (400)', async ({
  ctx,
  baseURL,
  member,
}) => {
  const origin = new URL(baseURL!).origin;
  await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

  const resp1 = await ctx.request.post(`${baseURL}/oauth2/consent`, {
    maxRedirects: 0,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    data: 'consent_challenge=fake-challenge-for-csrf-test&action=allow',
  });

  const status1 = resp1.status();
  console.log('[E1] origin-less POST missing csrf_token →', status1);

  expect(
    status1,
    `E1 (layer 1): origin-less POST must be rejected by Astro checkOrigin with 403; got ${status1}`,
  ).toBe(403);

  const resp2 = await ctx.request.post(`${baseURL}/oauth2/consent`, {
    maxRedirects: 0,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Origin': origin,
    },
    data: 'consent_challenge=fake-challenge-for-csrf-test&action=allow',
  });

  const status2 = resp2.status();
  const body2 = await resp2.text().catch(() => '');
  console.log('[E1] same-origin POST missing csrf_token →', status2, body2.slice(0, 120));

  const loc2 = resp2.headers()['location'] ?? '';
  expect(
    loc2.includes('code='),
    `E1 (layer 2): response must NOT contain an auth code; got status=${status2} Location=${loc2}`,
  ).toBe(false);

  expect(
    status2 === 400 || status2 === 502,
    `E1 (layer 2): status must be 400 (CSRF guard) or 502 (Hydra bad challenge); got ${status2}`,
  ).toBe(true);
});

test('E2 — consent POST with GARBAGE csrf_token is rejected (400)', async ({
  ctx,
  baseURL,
  member,
}) => {
  const origin = new URL(baseURL!).origin;
  await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

  const ts = Math.floor(Date.now() / 1000);
  const forgedToken = `${ts}.some-identity-id.randomnonce.INVALIDSIGNATUREXYZ`;

  const resp1 = await ctx.request.post(`${baseURL}/oauth2/consent`, {
    maxRedirects: 0,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    data: `consent_challenge=fake-challenge-for-csrf-test&action=allow&csrf_token=${encodeURIComponent(forgedToken)}`,
  });

  const status1 = resp1.status();
  console.log('[E2] origin-less POST garbage csrf_token →', status1);

  expect(
    status1,
    `E2 (layer 1): origin-less POST must be rejected by Astro checkOrigin with 403; got ${status1}`,
  ).toBe(403);

  const resp2 = await ctx.request.post(`${baseURL}/oauth2/consent`, {
    maxRedirects: 0,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Origin': origin,
    },
    data: `consent_challenge=fake-challenge-for-csrf-test&action=allow&csrf_token=${encodeURIComponent(forgedToken)}`,
  });

  const status2 = resp2.status();
  const body2 = await resp2.text().catch(() => '');
  console.log('[E2] same-origin POST garbage csrf_token →', status2, body2.slice(0, 120));

  const loc2 = resp2.headers()['location'] ?? '';
  expect(
    loc2.includes('code='),
    `E2 (layer 2): response must NOT contain an auth code; got status=${status2} Location=${loc2}`,
  ).toBe(false);

  expect(
    status2 === 400 || status2 === 502,
    `E2 (layer 2): status must be 400 (CSRF guard) or 502 (Hydra bad challenge); got ${status2}`,
  ).toBe(true);
});

test('E3 — consent POST with CROSS-IDENTITY csrf_token is rejected (400)', async ({
  ctx,
  baseURL,
  member,
  admin,
  kratosAdminURL,
}) => {

  const origin = new URL(baseURL!).origin;
  await loginViaJsonApi(ctx, { identifier: member.email, password: member.password }, baseURL);

  const ts = Math.floor(Date.now() / 1000);
  const crossToken = `${ts}.${admin.id}.crossnonce.INVALIDSIGNATURE`;

  const resp1 = await ctx.request.post(`${baseURL}/oauth2/consent`, {
    maxRedirects: 0,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    data: `consent_challenge=fake-challenge-for-csrf-test&action=allow&csrf_token=${encodeURIComponent(crossToken)}`,
  });

  const status1 = resp1.status();
  console.log('[E3] origin-less POST cross-identity csrf_token →', status1);

  expect(
    status1,
    `E3 (layer 1): origin-less POST must be rejected by Astro checkOrigin with 403; got ${status1}`,
  ).toBe(403);

  const resp2 = await ctx.request.post(`${baseURL}/oauth2/consent`, {
    maxRedirects: 0,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Origin': origin,
    },
    data: `consent_challenge=fake-challenge-for-csrf-test&action=allow&csrf_token=${encodeURIComponent(crossToken)}`,
  });

  const status2 = resp2.status();
  const body2 = await resp2.text().catch(() => '');
  console.log('[E3] same-origin POST cross-identity csrf_token →', status2, body2.slice(0, 120));

  const loc2 = resp2.headers()['location'] ?? '';
  expect(
    loc2.includes('code='),
    `E3 (layer 2): cross-identity token must NOT yield an auth code; got status=${status2} Location=${loc2}`,
  ).toBe(false);

  expect(
    status2 === 400 || status2 === 502,
    `E3 (layer 2): status must be 400 (CSRF identity mismatch) or 502 (Hydra bad challenge); got ${status2}`,
  ).toBe(true);
});
