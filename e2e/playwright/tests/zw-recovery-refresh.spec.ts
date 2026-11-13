// ZW — admin recovery Step D, past the privileged window: the passkey enrolled in the recovered session is what
// signs the admin in again when settings asks for a fresh sign-in (docs/runbooks/admin-recovery.md).
//
// The recovered session stays privileged for the flow's privileged_session_max_age (five minutes), after which settings
// redirects to a login flow with refresh=true. Waiting that long would hold the single e2e runner, and shortening
// the age in the shared Kratos overlay would put every spec that signs in and then edits settings on a clock, so the
// walk opens the same refresh login flow directly.

import { test, expect, adminAal2Context } from '../fixtures';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';
import { getSession } from '../actions/session';
import { addPlatformAuthenticator, passkeySignIn, registerPasskey } from '../actions/passkey';

async function adminApi(kratosAdminURL: string, method: string, path: string, body?: unknown): Promise<Response> {
  return fetch(`${kratosAdminURL}/admin/${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

test('ZW1 — after recovery the new passkey refreshes the session and settings opens without the deleted second factor', async ({
  browser,
  baseURL,
  kratosAdminURL,
  page,
}) => {
  const suffix = Date.now();
  const seeded = await createIdentityWithPassword({
    email: `zw1.admin.${suffix}@othala.test`,
    username: `zw1.admin.${suffix}`,
    displayName: 'ZW1 Admin',
    groups: ['everyone'],
    isAdmin: true,
    kratosAdminURL,
  });
  // The admin holds an authenticator app; the phone is then "lost".
  const enrol = await adminAal2Context({ browser, email: seeded.email, password: TEST_PASSWORD, baseURL: baseURL! });
  await enrol.close();

  // Steps 1 and 3 of the runbook: clear the marker, issue the code, redeem link and code in a fresh browser.
  const cleared = await adminApi(kratosAdminURL, 'PATCH', `identities/${seeded.id}`, [{ op: 'remove', path: '/metadata_admin/admin' }]);
  expect(cleared.ok, 'ZW1: the marker is cleared').toBe(true);
  const issued = await adminApi(kratosAdminURL, 'POST', 'recovery/code', { identity_id: seeded.id, expires_in: '1h' });
  expect(issued.ok, 'ZW1: the recovery code is issued').toBe(true);
  const { recovery_link: link, recovery_code: code } = (await issued.json()) as { recovery_link: string; recovery_code: string };
  await page.goto(link, { waitUntil: 'networkidle' });
  await page.locator('input[name="code"]').fill(code);
  await page.locator('form:has(input[name="code"]) button[name="method"]').click();
  await page.waitForURL((u) => !u.pathname.startsWith('/auth/recovery'), { timeout: 15_000 });

  // Step 2: delete the second factor the admin can no longer answer.
  const deleted = await adminApi(kratosAdminURL, 'DELETE', `identities/${seeded.id}/credentials/totp`);
  expect(deleted.status, 'ZW1: the app credential is deleted').toBe(204);
  const noCodes = await adminApi(kratosAdminURL, 'DELETE', `identities/${seeded.id}/credentials/lookup_secret`);
  expect([204, 404], 'ZW1: an absent backup-code credential is not an error that matters').toContain(noCodes.status);

  // Step D: the recovered session enrols a new passkey.
  const ctx = page.context();
  await addPlatformAuthenticator(ctx, page);
  await registerPasskey(page, baseURL!);
  await expect
    .poll(async () => Boolean((await readIdentity(kratosAdminURL, seeded.id, ['passkey'])).credentials?.passkey), {
      timeout: 10_000,
      message: 'ZW1: the new passkey is stored',
    })
    .toBe(true);
  const before = await getSession(ctx, baseURL!);
  expect(before?.authenticator_assurance_level, 'ZW1: the recovered session is first factor only').toBe('aal1');

  // The privileged window is over: settings would now send the admin to a refresh sign-in. The new passkey answers it.
  await passkeySignIn(page, `${baseURL}/self-service/login/browser?refresh=true&return_to=${encodeURIComponent(`${baseURL}/auth/settings`)}`);
  const after = await getSession(ctx, baseURL!);
  expect(after?.active, 'ZW1: the refreshed session is active').toBe(true);
  expect(after?.identity.id, 'ZW1: it is the same person').toBe(seeded.id);
  expect(after?.authenticator_assurance_level, 'ZW1: the passkey alone needs no second factor').toBe('aal1');
  expect(Date.parse(String(after?.authenticated_at)), 'ZW1: the sign-in is newer than the recovered session').toBeGreaterThan(
    Date.parse(String(before?.authenticated_at)),
  );
  const methods = ((after?.authentication_methods ?? []) as Array<{ method: string }>).map((m) => m.method);
  expect(methods, 'ZW1: the refresh was answered by the passkey').toContain('passkey');

  await page.goto(`${baseURL}/auth/settings`, { waitUntil: 'networkidle' });
  expect(new URL(page.url()).pathname, 'ZW1: settings opens, and does not ask for the deleted second factor').toBe('/auth/settings');

  // Step 5: restore the marker.
  const restored = await adminApi(kratosAdminURL, 'PATCH', `identities/${seeded.id}`, [{ op: 'add', path: '/metadata_admin/admin', value: true }]);
  expect(restored.ok, 'ZW1: the marker is restored').toBe(true);
});
