// ZZ — a refresh needs a live Kratos session: the token hook ends refresh chains with the session cap.

import { test, expect, KRATOS_ADMIN_URL } from '../fixtures';
import { createIdentityWithPassword } from '../actions/identity';
import { adminApi } from '../actions/kratos-admin';
import { expectRefreshRefused, refreshOnce, liveRefreshToken } from '../actions/grants';

test('ZZ1 — a refresh succeeds while the session lives and is refused once its sessions are revoked', async ({ browser, baseURL, hydraPublicURL }) => {
  const username = `zz1.member.${Date.now()}`;
  const member = await createIdentityWithPassword({
    email: `${username}@othala.test`,
    username,
    displayName: 'ZZ1 Member',
    groups: ['everyone', 'grafana-access'],
    kratosAdminURL: KRATOS_ADMIN_URL,
  });
  // liveRefreshToken's control refresh already passed with the session alive; this one pins the same on the returned token.
  const live = await liveRefreshToken({ browser, baseURL: baseURL!, hydraPublicURL, email: member.email });
  const rotated = await refreshOnce(browser, hydraPublicURL, live);
  expect(rotated, 'guard: a refresh with a live session passes the hook').toBeTruthy();

  const revoked = await adminApi(KRATOS_ADMIN_URL, 'DELETE', `identities/${member.id}/sessions`);
  expect(revoked.ok, `session revoke: ${revoked.status}`).toBe(true);
  await expectRefreshRefused(browser, hydraPublicURL, rotated!, 'guard: a refresh with no active session is refused by the token hook');
});
