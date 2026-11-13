// ZX — lost-device eviction for an admin target: another admin revokes the target's admin access, removes the app,
// issues a setup link, and grants admin back once the target holds a second factor again
// (docs/runbooks/lost-device.md, "An admin").

import type { Browser, BrowserContext } from 'playwright-core';
import { test, expect, adminAal2Context, enrollTotpSecret } from '../fixtures';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';
import { adminPoster } from '../actions/admin-post';

async function memberWithTotp(browser: Browser, baseURL: string, who: { email: string }): Promise<BrowserContext> {
  const ctx = await browser.newContext();
  await loginViaJsonApi(ctx, { identifier: who.email, password: TEST_PASSWORD }, baseURL);
  await enrollTotpSecret(ctx, baseURL);
  return ctx;
}

const hasTotp = async (kratosAdminURL: string, id: string): Promise<boolean> =>
  Boolean((await readIdentity(kratosAdminURL, id, ['totp'])).credentials?.totp);

const isAdmin = async (kratosAdminURL: string, id: string): Promise<boolean> =>
  Boolean((await readIdentity(kratosAdminURL, id)).metadata_admin?.admin);

test('ZX1 — an admin is evicted by revoking admin access, removing the app, issuing a setup link and granting admin again', async ({
  browser,
  baseURL,
  kratosAdminURL,
}) => {
  const suffix = Date.now();
  const seed = (label: string, groups: string[], admin = false) =>
    createIdentityWithPassword({
      email: `zx1.${label}.${suffix}@othala.test`,
      username: `zx1.${label}.${suffix}`,
      displayName: `ZX1 ${label}`,
      groups,
      isAdmin: admin,
      kratosAdminURL,
    });
  // Two admins, so the portal does not block revoking the target's access as the last one. Every real person
  // carries the household group; a save without one is refused whole.
  const actor = await seed('actor', ['everyone'], true);
  const target = await seed('target', ['everyone', 'grafana-access'], true);
  // A member with no elevated role and an app, on whose page the removal form is offered: the token binds to the admin
  // and the action, not to the person it is posted at.
  const bystander = await seed('bystander', ['everyone', 'grafana-access']);

  const targetCtx = await adminAal2Context({ browser, email: target.email, password: TEST_PASSWORD, baseURL: baseURL! });
  const bystanderCtx = await memberWithTotp(browser, baseURL!, bystander);
  const actorCtx = await adminAal2Context({ browser, email: actor.email, password: TEST_PASSWORD, baseURL: baseURL! });
  let returnedCtx: BrowserContext | null = null;
  try {
    expect(await hasTotp(kratosAdminURL, target.id), 'ZX1: the target holds an authenticator app').toBe(true);
    expect(await isAdmin(kratosAdminURL, target.id), 'ZX1: the target is an admin').toBe(true);

    const page = await actorCtx.newPage();
    const post = adminPoster(actorCtx, page, baseURL!, 'ZX1');

    // 1. The removal is refused while the target is an admin.
    await post(target.id, bystander.id, 'remove-credential', { cred_type: 'totp' }, true);
    expect(await hasTotp(kratosAdminURL, target.id), 'ZX1: the app stays while the target is an admin').toBe(true);

    // 2. Revoke the target's admin access.
    await post(target.id, target.id, 'revoke-admin');
    expect(await isAdmin(kratosAdminURL, target.id), 'ZX1: admin access is revoked').toBe(false);

    // 3. Remove the app; the target's sessions end.
    await post(target.id, bystander.id, 'remove-credential', { cred_type: 'totp' });
    expect(await hasTotp(kratosAdminURL, target.id), 'ZX1: the app is removed').toBe(false);
    expect(await getSession(targetCtx, baseURL!), 'ZX1: the lost device is signed out').toBeNull();

    // 4. A setup link is issued.
    const html = await post(target.id, target.id, 'issue-recovery');
    expect(html, 'ZX1: the setup link is shown').toContain('id="recoveryUrl"');

    // 5. The target sets up a second factor again, and admin access can be granted back.
    returnedCtx = await memberWithTotp(browser, baseURL!, target);
    await post(target.id, target.id, 'grant-admin');
    expect(await isAdmin(kratosAdminURL, target.id), 'ZX1: admin access is granted again').toBe(true);
  } finally {
    await actorCtx.close();
    await targetCtx.close();
    await bystanderCtx.close();
    await returnedCtx?.close();
  }
});
