// ZD — a second member on the same browser reaches the RP without a redirect loop.

import { test, expect, KRATOS_ADMIN_URL } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { hasSession } from '../actions/session';
import { walk } from '../actions/oidc';

const GRAFANA_CALLBACK = 'https://grafana.othala.test';
const MAX_HOPS = 8;

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
  ctx,
  baseURL,
}) => {
  const a = await seedMember('a');
  const b = await seedMember('b');
  await loginViaJsonApi(ctx, { identifier: a.email, password: TEST_PASSWORD }, baseURL!);
  const first = await walk(ctx, baseURL!, authorizeURL(baseURL!, 'a'), (loc) => loc.href.startsWith(GRAFANA_CALLBACK));
  expect(first.at(-1)?.searchParams.get('code'), `A must be authorised; chain: ${first.map(String).join(' -> ')}`).toBeTruthy();

  const page = await ctx.newPage();
  await page.goto(`${baseURL}/`, { waitUntil: 'networkidle' });
  await Promise.all([
    page.waitForResponse((r) => r.url().startsWith(`${baseURL}/auth/logout`) && r.request().method() === 'POST'),
    page.getByRole('button', { name: 'Sign out', exact: true }).click(),
  ]);
  await expect(page.getByRole('link', { name: 'Sign in', exact: true })).toBeVisible({ timeout: 15_000 });
  expect(await hasSession(ctx, baseURL!), 'A signed out').toBe(false);

  await loginViaJsonApi(ctx, { identifier: b.email, password: TEST_PASSWORD }, baseURL!);
  const second = await walk(ctx, baseURL!, authorizeURL(baseURL!, 'b'), (loc) => loc.href.startsWith(GRAFANA_CALLBACK));
  const chain = second.map(String).join(' -> ');
  expect(second.length, `B must reach the RP within ${MAX_HOPS} hops; chain: ${chain}`).toBeLessThanOrEqual(MAX_HOPS);
  expect(second.at(-1)?.searchParams.get('code'), `B must be authorised; chain: ${chain}`).toBeTruthy();
});
