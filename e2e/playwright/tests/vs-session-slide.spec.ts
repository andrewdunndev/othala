// VS — loading the landing extends the session and hands the browser the reissued cookie, never moving authenticated_at;
// a disabled session is not revived by a landing visit. The overlay sets earliest_possible_extend to the lifespan, so
// every visit extends.

import { test, expect } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';

const COOKIE = 'ory_kratos_session';

async function signedIn(ctx: Parameters<typeof getSession>[0], baseURL: string, kratosAdminURL: string, tag: string) {
  const suffix = `${tag}.${Date.now()}`;
  const member = await createIdentityWithPassword({
    email: `slide.${suffix}@othala.test`,
    username: `slide.${suffix}`,
    displayName: 'Slide',
    groups: [],
    kratosAdminURL,
  });
  await loginViaJsonApi(ctx, { identifier: member.email, password: TEST_PASSWORD }, baseURL);
}

test('VS1 — the landing extends the session and moves the browser cookie, not authenticated_at', async ({ ctx, baseURL, kratosAdminURL }) => {
  await signedIn(ctx, baseURL!, kratosAdminURL, 'vs1');
  const cookieOf = async () => (await ctx.cookies()).find((c) => c.name === COOKIE)!;
  const before = await getSession(ctx, baseURL!);
  const cookieBefore = await cookieOf();

  await new Promise((r) => setTimeout(r, 3000));
  const page = await ctx.newPage();
  await page.goto(`${baseURL}/`, { waitUntil: 'networkidle' });

  // Read before any whoami from the context, which would reissue the cookie itself and mask a landing that drops it.
  const cookieAfter = await cookieOf();
  const after = await getSession(ctx, baseURL!);
  expect(Date.parse(String(after!.expires_at)), 'expires_at moved').toBeGreaterThan(Date.parse(String(before!.expires_at)));
  expect(after!.authenticated_at, 'authenticated_at unchanged').toBe(before!.authenticated_at);
  expect(cookieAfter.expires, 'browser cookie expiry moved').toBeGreaterThan(cookieBefore.expires);
});

test('VS2 — a disabled session is not revived by a landing visit', async ({ ctx, baseURL, kratosAdminURL }) => {
  await signedIn(ctx, baseURL!, kratosAdminURL, 'vs2');
  const session = await getSession(ctx, baseURL!);
  const res = await ctx.request.delete(`${kratosAdminURL}/admin/sessions/${session!.id}`);
  expect(res.ok(), `disable answered ${res.status()}`).toBe(true);

  const page = await ctx.newPage();
  await page.goto(`${baseURL}/`, { waitUntil: 'networkidle' });
  await expect(page.getByRole('link', { name: 'Sign in', exact: true })).toBeVisible({ timeout: 15_000 });
  expect(await getSession(ctx, baseURL!), 'session after the visit').toBeNull();
});
