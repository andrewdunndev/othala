// ZV — lost-device eviction for a member who holds an elevated role: removal is refused until the role is lowered,
// then the app is removed and the sessions end, a setup link is issued, and the role can be raised once a second
// factor exists again (docs/runbooks/lost-device.md).

import type { Browser, BrowserContext } from 'playwright-core';
import { test, expect, adminAal2Context, enrollTotpSecret } from '../fixtures';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';
import { csrfTokenFor, postAdminAction } from '../actions/admin-post';

async function memberWithTotp(browser: Browser, baseURL: string, who: { id: string; email: string }): Promise<BrowserContext> {
  const ctx = await browser.newContext();
  await loginViaJsonApi(ctx, { identifier: who.email, password: TEST_PASSWORD }, baseURL);
  await enrollTotpSecret(ctx, baseURL);
  return ctx;
}

const hasTotp = async (kratosAdminURL: string, id: string): Promise<boolean> =>
  Boolean((await readIdentity(kratosAdminURL, id, ['totp'])).credentials?.totp);

const groupsOf = async (kratosAdminURL: string, id: string): Promise<string[]> =>
  ((await readIdentity(kratosAdminURL, id)).metadata_admin?.groups ?? []) as string[];

test('ZV1 — an elevated member is evicted by lowering the role, removing the app, issuing a setup link and raising it again', async ({
  browser,
  baseURL,
  kratosAdminURL,
}) => {
  const suffix = Date.now();
  const seed = (label: string, groups: string[], isAdmin = false) =>
    createIdentityWithPassword({
      email: `zv1.${label}.${suffix}@othala.test`,
      username: `zv1.${label}.${suffix}`,
      displayName: `ZV1 ${label}`,
      groups,
      isAdmin,
      kratosAdminURL,
    });
  const admin = await seed('admin', [], true);
  // Every real member carries the household group; a save without one is refused whole.
  const member = await seed('member', ['everyone', 'grafana-access', 'grafana-admin']);
  // A member with no elevated role, on whose page the removal form is offered: the token binds to the admin and the
  // action, not to the person it is posted at.
  const bystander = await seed('bystander', ['everyone', 'grafana-access']);

  const memberCtx = await memberWithTotp(browser, baseURL!, member);
  const bystanderCtx = await memberWithTotp(browser, baseURL!, bystander);
  const adminCtx = await adminAal2Context({ browser, email: admin.email, password: TEST_PASSWORD, baseURL: baseURL! });
  let raisedCtx: BrowserContext | null = null;
  try {
    const page = await adminCtx.newPage();
    // The page answers 200 whether or not the action was accepted; a refusal is a danger notice carrying its reason.
    // Every step must say which it expects, so a refused save cannot pass unnoticed.
    const post = async (target: string, tokenFrom: string, action: string, fields: Record<string, string>, expectRefusal = false) => {
      await page.goto(`${baseURL}/admin/users/${tokenFrom}`, { waitUntil: 'networkidle' });
      const token = await csrfTokenFor(page, action);
      expect(token, `ZV1: ${action} is offered on the token page`).not.toBe('');
      const resp = await postAdminAction(adminCtx, baseURL!, target, { csrf_token: token, action, ...fields });
      expect(resp.status(), `ZV1: ${action} answers with the page`).toBe(200);
      const html = await resp.text();
      const refusal = html.match(/class="notice notice-danger[^"]*"[^>]*>([\s\S]*?)<\/div>/)?.[1]?.replace(/<[^>]*>/g, '').trim();
      if (expectRefusal) expect(refusal, `ZV1: ${action} is refused`).toBeTruthy();
      else expect(refusal, `ZV1: ${action} was refused: ${refusal}`).toBeUndefined();
      return html;
    };

    // 1. The removal is refused while the member holds the elevated role.
    await post(member.id, bystander.id, 'remove-credential', { cred_type: 'totp' }, true);
    expect(await hasTotp(kratosAdminURL, member.id), 'ZV1: the app stays while the role is elevated').toBe(true);

    // 2. Lower the role to the app's entry level.
    await post(member.id, member.id, 'save-access', { 'level:grafana': 'viewer' });
    expect(await groupsOf(kratosAdminURL, member.id), 'ZV1: the household group is kept').toContain('everyone');
    expect(await groupsOf(kratosAdminURL, member.id), 'ZV1: the elevated group is gone').not.toContain('grafana-admin');

    // 3. Remove the app; the member's sessions end.
    await post(member.id, bystander.id, 'remove-credential', { cred_type: 'totp' });
    expect(await hasTotp(kratosAdminURL, member.id), 'ZV1: the app is removed').toBe(false);
    expect(await getSession(memberCtx, baseURL!), 'ZV1: the lost device is signed out').toBeNull();

    // 4. A setup link is issued.
    const html = await post(member.id, member.id, 'issue-recovery', {});
    expect(html, 'ZV1: the setup link is shown').toContain('id="recoveryUrl"');

    // 5. The member sets up a second factor again, and the role can be raised.
    raisedCtx = await memberWithTotp(browser, baseURL!, member);
    await post(member.id, member.id, 'save-access', { 'level:grafana': 'admin' });
    expect(await groupsOf(kratosAdminURL, member.id), 'ZV1: the role is raised again').toContain('grafana-admin');
  } finally {
    await adminCtx.close();
    await memberCtx.close();
    await bystanderCtx.close();
    await raisedCtx?.close();
  }
});
