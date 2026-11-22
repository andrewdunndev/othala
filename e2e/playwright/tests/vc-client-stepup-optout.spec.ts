// VC — a client with consent.skip_step_up takes a passkey-only aal1 session, an admin-marked member included; the admin
// pages, forward-auth and every unflagged client keep asking for aal2; the tile opens presentation.launch_url.

import type { Page } from '@playwright/test';
import { test, expect, enrollTotpSecret, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { registerPasskey, passkeySignIn } from '../actions/passkey';
import { getSession } from '../actions/session';
import { walk } from '../actions/oidc';

const OPT_OUT_CLIENT = 'audiobookshelf';
const OPT_OUT_ORIGIN = 'https://audiobookshelf.othala.test';
const OPT_OUT_REDIRECT = `${OPT_OUT_ORIGIN}/auth/openid/callback`;
const LAUNCH_URL = `${OPT_OUT_ORIGIN}/login#/sso?identifier=dag`;
const GROUPS = ['grafana-access', 'audiobookshelf-access'];

const authorizeUrl = (baseURL: string, client: string, redirect: string) =>
  `${baseURL}/oauth2/auth?client_id=${client}&response_type=code` +
  `&scope=${encodeURIComponent('openid email groups')}` +
  `&redirect_uri=${encodeURIComponent(redirect)}&state=vc-state&nonce=vc-nonce`;

const isAsk = (url: string) => /aal=aal2|\/auth\/login/.test(url);

/** Requests that ask for a login flow or a second factor. */
function recordAsks(page: Page): string[] {
  const asks: string[] = [];
  page.on('request', (r) => {
    if (isAsk(r.url())) asks.push(r.url());
  });
  return asks;
}

async function seed(slug: string, kratosAdminURL: string, isAdmin: boolean): Promise<string> {
  const username = `${slug}.${Date.now()}`;
  const email = `${username}@othala.test`;
  await createIdentityWithPassword({ email, username, displayName: `VC ${slug}`, groups: GROUPS, isAdmin, kratosAdminURL });
  return email;
}

test('VC1-VC4 — an admin-marked member with a passkey and TOTP signs in to the opted-out client on the passkey alone', async ({
  baseURL,
  kratosAdminURL,
  page,
  virtualAuthenticator,
}) => {
  test.setTimeout(120_000);
  expect(virtualAuthenticator.authenticatorId, 'VC: virtual authenticator is attached').toBeTruthy();
  const ctx = page.context();
  const email = await seed('vc1.admin', kratosAdminURL, true);
  await loginViaJsonApi(ctx, { identifier: email, password: TEST_PASSWORD }, baseURL!);
  await registerPasskey(page, baseURL!);
  await enrollTotpSecret(ctx, baseURL!);
  await ctx.clearCookies();

  // The sign-in starts at the opted-out client's authorize URL, with the passkey as the only factor given. The app host does
  // not resolve in the browser, so the redirect to it is read from the recorded requests.
  const seen: string[] = [];
  page.on('request', (r) => seen.push(r.url()));
  const asks = recordAsks(page);
  await passkeySignIn(page, authorizeUrl(baseURL!, OPT_OUT_CLIENT, OPT_OUT_REDIRECT)).catch(() => {});
  await expect
    .poll(() => seen.some((u) => u.startsWith(`${OPT_OUT_REDIRECT}?`) && /[?&]code=/.test(u)), {
      message: 'VC1: the browser is sent to redirect_uri?code=',
      timeout: 20_000,
    })
    .toBe(true);
  expect(asks.filter((u) => u.includes('aal=aal2')), 'VC1: no request asks for aal2').toEqual([]);
  await expect(page.locator('#totp-code'), 'VC1: the TOTP form never renders').toHaveCount(0);
  expect((await getSession(ctx, baseURL!))?.authenticator_assurance_level, 'VC1: the session is aal1').toBe('aal1');

  // VC2: the same session on a client without the flag is asked.
  const grafana = await walk(ctx, baseURL!, authorizeUrl(baseURL!, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI), (loc) => isAsk(loc.toString()));
  const ask = grafana.at(-1);
  expect(ask?.pathname, `VC2: the unflagged client steps up, hops ${grafana.join(' > ')}`).toBe('/auth/login');
  expect(ask?.searchParams.get('aal'), 'VC2: the step-up asks for aal2').toBe('aal2');

  // VC3: the portal admin pages still step up for the same session.
  const admin = await ctx.request.get(`${baseURL}/admin`, { maxRedirects: 0 });
  const adminLoc = new URL(admin.headers()['location'] ?? '', baseURL!);
  expect(admin.status(), 'VC3: /admin redirects an aal1 session').toBeGreaterThanOrEqual(300);
  expect(adminLoc.href, 'VC3: /admin sends the session to step up').toMatch(/aal=aal2|\/auth\/login|\/self-service\/login/);

  // VC4: forward-auth reads no opt-out.
  const fa = await ctx.request.get(`${baseURL}/api/forward-auth?group=grafana-access`, { maxRedirects: 0 });
  expect(fa.status(), 'VC4: forward-auth refuses the aal1 session').toBe(401);
});

test('VC5 — the tile opens presentation.launch_url', async ({ baseURL, kratosAdminURL, page, virtualAuthenticator }) => {
  test.setTimeout(90_000);
  expect(virtualAuthenticator.authenticatorId, 'VC5: virtual authenticator is attached').toBeTruthy();
  const ctx = page.context();
  const email = await seed('vc5.member', kratosAdminURL, false);
  await loginViaJsonApi(ctx, { identifier: email, password: TEST_PASSWORD }, baseURL!);
  await registerPasskey(page, baseURL!);
  await ctx.clearCookies();

  await passkeySignIn(page, `${baseURL}/auth/login`);
  await page.waitForURL((u) => u.pathname === '/', { timeout: 15_000 });
  const tile = page.locator(`.tile[data-slug="${OPT_OUT_CLIENT}"] a.tile-launch`);
  await expect(tile, 'VC5: the tile links to launch_url, not url').toHaveAttribute('href', LAUNCH_URL);
  const grafanaTile = page.locator('.tile[data-slug="grafana"] a.tile-launch');
  await expect(grafanaTile, 'VC5: a tile with no launch_url keeps url').toHaveAttribute('href', 'https://grafana.othala.test');
});
