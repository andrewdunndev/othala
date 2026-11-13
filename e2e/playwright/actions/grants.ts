/**
 * grants.ts — an app's refresh token, and proof the server refuses it after an account change.
 *
 * Needs GRAFANA_CLIENT_SECRET in the environment (the e2e compose passes it to the tester).
 */

import type { Browser, BrowserContext } from '@playwright/test';
import { expect } from '@playwright/test';
import { GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI } from '../fixtures';
import { loginViaJsonApi } from './login';
import { requireEnv } from './oidc';
import { TEST_PASSWORD } from './identity';

async function authorizeOffline(ctx: BrowserContext, baseURL: string): Promise<string> {
  let url =
    `${baseURL}/oauth2/auth` +
    `?client_id=${GRAFANA_CLIENT_ID}` +
    `&response_type=code` +
    `&scope=${encodeURIComponent('openid email groups offline_access')}` +
    `&redirect_uri=${encodeURIComponent(GRAFANA_REDIRECT_URI)}` +
    `&state=grants-state` +
    `&nonce=grants-nonce`;
  for (let hop = 0; hop < 10; hop++) {
    const resp = await ctx.request.get(url, { maxRedirects: 0 });
    const loc = resp.headers()['location'];
    if (!loc) throw new Error(`authorize chain stalled at hop ${hop} (${url}): status ${resp.status()}`);
    const parsed = new URL(loc, baseURL);
    if (parsed.searchParams.get('error')) throw new Error(`authorize denied: ${loc}`);
    if (loc.startsWith('https://grafana.othala.test')) {
      const code = parsed.searchParams.get('code');
      if (!code) throw new Error(`no code at terminus: ${loc}`);
      return code;
    }
    url = parsed.toString();
  }
  throw new Error(`authorize chain did not terminate in 10 hops (last: ${url})`);
}

async function tokenGrant(ctx: BrowserContext, hydraPublicURL: string, form: Record<string, string>) {
  const basic = Buffer.from(`${GRAFANA_CLIENT_ID}:${requireEnv('GRAFANA_CLIENT_SECRET')}`).toString('base64');
  return ctx.request.post(`${hydraPublicURL}/oauth2/token`, {
    headers: { Authorization: `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    form,
  });
}

/** Signs the person in, takes an offline grant, rotates it once to prove it works, and returns the live token. */
export async function liveRefreshToken(opts: {
  browser: Browser;
  baseURL: string;
  hydraPublicURL: string;
  email: string;
}): Promise<string> {
  const ctx = await opts.browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: opts.email, password: TEST_PASSWORD }, opts.baseURL);
    const code = await authorizeOffline(ctx, opts.baseURL);
    const exchange = await tokenGrant(ctx, opts.hydraPublicURL, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: GRAFANA_REDIRECT_URI,
    });
    expect(exchange.ok(), `code exchange failed: ${exchange.status()}`).toBe(true);
    const first = (await exchange.json()).refresh_token as string | undefined;
    expect(first, 'offline_access must yield a refresh_token').toBeTruthy();

    const control = await tokenGrant(ctx, opts.hydraPublicURL, { grant_type: 'refresh_token', refresh_token: first! });
    expect(control.ok(), `control refresh must succeed before the change: ${control.status()}`).toBe(true);
    const rotated = (await control.json()).refresh_token as string | undefined;
    expect(rotated, 'the refresh grant must rotate the refresh_token').toBeTruthy();
    return rotated!;
  } finally {
    await ctx.close();
  }
}

export async function expectRefreshRefused(browser: Browser, hydraPublicURL: string, refreshToken: string, why: string) {
  const ctx = await browser.newContext();
  try {
    const resp = await tokenGrant(ctx, hydraPublicURL, { grant_type: 'refresh_token', refresh_token: refreshToken });
    expect([400, 401], `${why}: refresh must be refused; got ${resp.status()}`).toContain(resp.status());
  } finally {
    await ctx.close();
  }
}
