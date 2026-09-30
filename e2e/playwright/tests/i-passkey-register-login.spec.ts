// I — a passkey registers and then logs in usernameless (CDP virtual authenticator).

import { test, expect } from '../fixtures';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';
import { capturePasskeyLoginDiagnostics, probePasskeyLoginCapabilities } from '../actions/diagnostics';

const PASSKEY_REGISTER_BUTTON = 'button[name="passkey_register_trigger"]';

const PASSKEY_LOGIN_BUTTON = 'button[name="passkey_login_trigger"]';

test.describe('I — Passkey register → usernameless login', () => {
  test('I1 — register a passkey via settings, then log in usernameless', async ({
    browser,
    baseURL,
    kratosAdminURL,
    page,
    virtualAuthenticator,
  }) => {
    console.log('[I1] virtual authenticator id:', virtualAuthenticator.authenticatorId);

    page.on('pageerror', (err) => console.log('[I1] page error:', err.message));

    const identity = await createIdentityWithPassword({
      email: 'passkey.tester@othala.test',
      username: 'passkey.tester',
      displayName: 'Passkey Tester',
      groups: [],
      kratosAdminURL,
    });
    console.log('[I1] seeded identity:', identity.id, identity.email);

    const ctx = page.context();
    await loginViaJsonApi(ctx, { identifier: identity.email, password: TEST_PASSWORD }, baseURL);

    const session = await getSession(ctx, baseURL);
    expect(session?.active, 'I1 precondition: must have active session before passkey registration').toBe(true);
    expect(session?.identity?.traits?.email).toBe(identity.email);
    console.log('[I1] session established, AAL:', session?.authenticator_assurance_level);

    await page.goto(`${baseURL}/auth/settings`);
    await page.waitForLoadState('networkidle');

    const registerBtn = page.locator(PASSKEY_REGISTER_BUTTON).first();
    await expect(registerBtn, 'I1: passkey register button must be visible on settings page').toBeVisible({ timeout: 10_000 });
    await page.waitForFunction(() => typeof (window as unknown as Record<string, unknown>).oryPasskeySettingsRegistration === 'function');
    await registerBtn.click();

    await page.waitForLoadState('networkidle');
    console.log('[I1] passkey registered, current URL:', page.url());

    const pageText = await page.textContent('body');
    expect(
      pageText,
      'I1: settings page must not show an error after passkey registration',
    ).not.toMatch(/error|something went wrong/i);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let registered: any;
    await expect.poll(
      async () => {
        registered = await readIdentity(kratosAdminURL, identity.id);
        return registered?.credentials?.passkey;
      },
      { timeout: 10_000, message: 'I1: identity must have a passkey credential recorded server-side after registration' },
    ).toBeTruthy();
    console.log('[I1] passkey credential record:', JSON.stringify(registered?.credentials?.passkey));

    const logoutResp = await ctx.request.get(`${baseURL}/self-service/logout/browser`, {
      headers: { Accept: 'application/json' },
    });
    if (logoutResp.ok()) {
      const logoutFlow = await logoutResp.json().catch(() => null);
      const logoutUrl: string = logoutFlow?.logout_url ?? '';
      if (logoutUrl) {
        await ctx.request.get(logoutUrl);
      }
    }
    await ctx.clearCookies();

    const afterLogout = await getSession(ctx, baseURL);
    expect(
      afterLogout,
      'I1 precondition (post-logout): session must be gone before usernameless login',
    ).toBeNull();

    await page.goto(`${baseURL}/auth/login`);
    await page.waitForLoadState('networkidle');

    console.log('[I1] login-page capability probe:', JSON.stringify(await probePasskeyLoginCapabilities(page)));

    let loginBtn = page.locator(PASSKEY_LOGIN_BUTTON).first();
    if (!(await loginBtn.isVisible().catch(() => false))) {
      await page.reload();
      await page.waitForLoadState('networkidle');
      loginBtn = page.locator(PASSKEY_LOGIN_BUTTON).first();
    }
    if (!(await loginBtn.isVisible().catch(() => false))) {
      await capturePasskeyLoginDiagnostics(page, 'I1-login-missing');
    }
    await expect(loginBtn, 'I1: passkey login button must be visible on the login page').toBeVisible({ timeout: 10_000 });
    await page.waitForFunction(() => typeof (window as unknown as Record<string, unknown>).oryPasskeyLogin === 'function');
    await loginBtn.click();

    await page.waitForURL((u) => !u.pathname.startsWith('/auth/login'), { timeout: 15_000 });
    console.log('[I1] post-passkey-login URL:', page.url());

    let finalSession: Awaited<ReturnType<typeof getSession>> = null;
    await expect.poll(
      async () => {
        finalSession = await getSession(ctx, baseURL);
        return finalSession?.active ?? false;
      },
      { timeout: 10_000, message: 'I1: session must become active after usernameless passkey login' },
    ).toBe(true);
    expect(
      finalSession!.identity?.traits?.email,
      'I1: session identity must match the passkey-registered identity',
    ).toBe(identity.email);

    console.log('[I1] PASS — passkey usernameless login succeeded for', identity.email);
  });
});
