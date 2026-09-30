/**
 * ZD — two members sharing one browser.
 *
 * A signs in, authorises grafana and signs out through the portal. B then signs
 * in from the same browser and authorises the same client. Hydra still holds
 * A's remembered login there, so the portal must end that login session and
 * let Hydra re-issue the request: B reaches the RP callback within a bounded
 * number of hops instead of looping between the login UI and Hydra.
 */

import { test, expect } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { hasSession } from '../actions/session';
import { walk } from '../actions/oidc';

const GRAFANA_CALLBACK = 'https://grafana.othala.test';
const MAX_HOPS = 8;
const KRATOS_ADMIN_URL = process.env.KRATOS_ADMIN_URL ?? 'http://kratos:4434';

function authorizeURL(baseURL: string, tag: string): string {
  return (
    `${baseURL}/oauth2/auth` +
    `?client_id=grafana` +
    `&response_type=code` +
    `&scope=${encodeURIComponent('openid email groups')}` +
    `&redirect_uri=${encodeURIComponent(`${GRAFANA_CALLBACK}/login/generic_oauth`)}` +
    `&state=zd-${tag}-state` +
    `&nonce=zd-${tag}-nonce`
  );
}

async function seedMember(tag: string) {
  const username = `zd.${tag}.${Date.now()}`;
  return createIdentityWithPassword({
    email: `${username}@othala.test`,
    username,
    displayName: `ZD ${tag}`,
    groups: ['family', 'grafana-access'],
    kratosAdminURL: KRATOS_ADMIN_URL,
  });
}

test('ZD — a second member signing in on the same browser reaches the RP without a redirect loop', async ({
  browser,
  baseURL,
}) => {
  const a = await seedMember('a');
  const b = await seedMember('b');
  const ctx = await browser.newContext();
  try {
    await loginViaJsonApi(ctx, { identifier: a.email, password: TEST_PASSWORD }, baseURL!);
    const first = await walk(ctx, baseURL!, authorizeURL(baseURL!, 'a'), (loc) => loc.href.startsWith(GRAFANA_CALLBACK));
    expect(first.at(-1)?.searchParams.get('code'), `A must be authorised; chain: ${first.map(String).join(' -> ')}`).toBeTruthy();

    // A signs out through the portal's own sign-out button.
    const page = await ctx.newPage();
    await page.goto(`${baseURL}/`, { waitUntil: 'networkidle' });
    await Promise.all([
      page.waitForResponse((r) => r.url().startsWith(`${baseURL}/auth/logout`) && r.request().method() === 'POST'),
      page.getByRole('button', { name: 'Sign out', exact: true }).click(),
    ]);
    await expect(page.getByRole('link', { name: 'Sign in', exact: true })).toBeVisible({ timeout: 15_000 });
    expect(await hasSession(ctx, baseURL!), 'A signed out').toBe(false);

    // B signs in on the same browser and authorises the same client.
    await loginViaJsonApi(ctx, { identifier: b.email, password: TEST_PASSWORD }, baseURL!);
    const second = await walk(ctx, baseURL!, authorizeURL(baseURL!, 'b'), (loc) => loc.href.startsWith(GRAFANA_CALLBACK));
    const chain = second.map(String).join(' -> ');
    expect(second.length, `B must reach the RP within ${MAX_HOPS} hops; chain: ${chain}`).toBeLessThanOrEqual(MAX_HOPS);
    expect(second.at(-1)?.searchParams.get('code'), `B must be authorised; chain: ${chain}`).toBeTruthy();
  } finally {
    await ctx.close();
  }
});
