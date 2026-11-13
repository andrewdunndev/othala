// P — credential eviction ends the lost device's sessions (HIGH-C).

import { test, expect, clientAddress } from '../fixtures';
import type { BrowserContext, CDPSession, Page } from 'playwright-core';
import { createIdentityWithPassword, readIdentity, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';
import { capturePasskeyLoginDiagnostics, probePasskeyLoginCapabilities } from '../actions/diagnostics';
import { clickAndSettle } from '../actions/passkey';

const PASSKEY_REGISTER_BUTTON = 'button[name="passkey_register_trigger"]';
const PASSKEY_LOGIN_BUTTON = 'button[name="passkey_login_trigger"]';

async function registerPasskeyForContext(
  page: Page,
  baseURL: string,
  identity: { id: string; email: string },
): Promise<void> {
  await page.goto(`${baseURL}/auth/settings`);
  await page.waitForLoadState('networkidle');
  const btn = page.locator(PASSKEY_REGISTER_BUTTON).first();
  await expect(btn, 'passkey register button must be visible').toBeVisible({ timeout: 10_000 });
  await page.waitForFunction(() => typeof (window as unknown as Record<string, unknown>).oryPasskeySettingsRegistration === 'function');
  await clickAndSettle(page, btn);
  console.log(`[P] passkey registered for ${identity.email} at URL:`, page.url());
}

async function passkeyLogin(page: Page, ctx: BrowserContext, baseURL: string, label: string) {
  await page.goto(`${baseURL}/auth/login`, { waitUntil: 'commit' }).catch(() => {});
  await page.waitForURL(/\/auth\/login\?flow=/, { timeout: 10_000 });
  await page.waitForLoadState('networkidle');
  console.log(`[${label}] login-page capability probe:`, JSON.stringify(await probePasskeyLoginCapabilities(page)));

  let loginBtn = page.locator(PASSKEY_LOGIN_BUTTON).first();
  if (!(await loginBtn.isVisible().catch(() => false))) {
    await page.reload();
    await page.waitForLoadState('networkidle');
    loginBtn = page.locator(PASSKEY_LOGIN_BUTTON).first();
  }
  if (!(await loginBtn.isVisible().catch(() => false))) {
    await capturePasskeyLoginDiagnostics(page, `${label}-login-missing`);
  }
  await expect(loginBtn, 'passkey login button must be visible').toBeVisible({ timeout: 10_000 });
  await page.waitForFunction(() => typeof (window as unknown as Record<string, unknown>).oryPasskeyLogin === 'function');
  await loginBtn.click();
  await page.waitForURL((u) => !u.pathname.startsWith('/auth/login'), { timeout: 15_000 }).catch(() => {});
  return getSession(ctx, baseURL);
}

async function clearSession(ctx: BrowserContext, baseURL: string): Promise<void> {
  const logoutResp = await ctx.request.get(`${baseURL}/self-service/logout/browser`, {
    headers: { Accept: 'application/json' },
  });
  if (logoutResp.ok()) {
    const flow = await logoutResp.json().catch(() => null);
    const logoutUrl: string = flow?.logout_url ?? '';
    if (logoutUrl) await ctx.request.get(logoutUrl);
  }
  await ctx.clearCookies();
}

// A context opened inside a test misses the fixture's per-test client address; each device is its own client to the edge.
async function newDeviceContext(browser: import('playwright-core').Browser, device: string) {
  const { testId, retry } = test.info();
  const ctx = await browser.newContext({ extraHTTPHeaders: { 'X-Forwarded-For': clientAddress(`${testId}:${retry}:${device}`) } });
  const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
    },
  });
  return { ctx, page, cdp, authenticatorId };
}

type Device = Awaited<ReturnType<typeof newDeviceContext>>;

// A victim with passkey A on one device and passkey B on another, both signed out. Each test seeds its own, so neither
// depends on the other having run.
async function enrollTwoPasskeys(browser: import('playwright-core').Browser, baseURL: string, kratosAdminURL: string) {
  const uniqueSuffix = Date.now();
  const identity = await createIdentityWithPassword({
    email: `evict.victim.${uniqueSuffix}@othala.test`,
    username: `evict.victim.${uniqueSuffix}`,
    displayName: 'Eviction Victim',
    groups: [],
    kratosAdminURL,
  });
  console.log('[P] seeded identity:', identity.id);

  const devA = await newDeviceContext(browser, 'A');
  await loginViaJsonApi(devA.ctx, { identifier: identity.email, password: TEST_PASSWORD }, baseURL);
  await registerPasskeyForContext(devA.page, baseURL, identity);

  const devB = await newDeviceContext(browser, 'B');
  console.log('[P] second virtual authenticator id:', devB.authenticatorId);
  await loginViaJsonApi(devB.ctx, { identifier: identity.email, password: TEST_PASSWORD }, baseURL);
  await registerPasskeyForContext(devB.page, baseURL, identity);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let registered: any;
  await expect.poll(
    async () => {
      registered = await readIdentity(kratosAdminURL, identity.id);
      return registered?.credentials?.passkey;
    },
    { timeout: 10_000, message: 'identity must have passkey credentials after both enrollments' },
  ).toBeTruthy();
  console.log('[P] passkey credential record:', JSON.stringify(registered?.credentials?.passkey));

  await clearSession(devA.ctx, baseURL);
  await clearSession(devB.ctx, baseURL);
  return { identity, devA, devB };
}

async function closeDevices(...devices: Device[]) {
  for (const dev of devices) {
    await dev.cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: dev.authenticatorId }).catch(() => {});
    await dev.cdp.detach().catch(() => {});
    await dev.ctx.close().catch(() => {});
  }
}

test.describe('P — Passkey credential eviction (lost-device scenario)', () => {
  test('P1 — victim enrolls passkey A; a second context enrolls passkey B', async ({ browser, baseURL, kratosAdminURL }) => {
    const { devA, devB } = await enrollTwoPasskeys(browser, baseURL, kratosAdminURL);
    await closeDevices(devA, devB);
  });

  test('P3 — victim self-removes the lost passkey; B locked out, A survives', async ({ browser, baseURL, kratosAdminURL }) => {
    const { identity, devA, devB } = await enrollTwoPasskeys(browser, baseURL, kratosAdminURL);
    const contextA = devA.ctx;
    const loginPageA = devA.page;
    const contextB = devB.ctx;
    const loginPageB = devB.page;

    await clearSession(contextB, baseURL);

    await loginViaJsonApi(contextA, { identifier: identity.email, password: TEST_PASSWORD }, baseURL);
    await loginPageA.goto(`${baseURL}/auth/settings`);
    await loginPageA.waitForLoadState('networkidle');

    const flowId = new URL(loginPageA.url()).searchParams.get('flow');
    if (!flowId) throw new Error('P3: settings page did not redirect with a ?flow= id');
    const flowResp = await contextA.request.get(
      `${baseURL}/self-service/settings/flows?id=${flowId}`,
      { headers: { Accept: 'application/json' } },
    );
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const flow: any = await flowResp.json();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const removeNodes = (flow?.ui?.nodes ?? []).filter(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (n: any) => n.group === 'passkey' && n.attributes?.name === 'passkey_remove',
    );
    expect(removeNodes.length, 'P3: settings flow must list both enrolled passkeys').toBe(2);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    removeNodes.sort((a: any, b: any) => (a.meta?.label?.context?.added_at_unix ?? 0) - (b.meta?.label?.context?.added_at_unix ?? 0));
    const passkeyBCredentialId = String(removeNodes[removeNodes.length - 1].attributes.value);
    console.log('[P3] passkey B credential id (hex):', passkeyBCredentialId);

    // The remove button sits behind the row's inline confirm.
    await loginPageA.locator(`li[data-credential-id="${passkeyBCredentialId}"] .lbl-remove`).click();
    const removeBtn = loginPageA.locator(`button[name="passkey_remove"][value="${passkeyBCredentialId}"]`);
    await expect(removeBtn, 'P3: passkey B remove button must be visible').toBeVisible({ timeout: 10_000 });
    await removeBtn.click();
    await loginPageA.waitForLoadState('networkidle');

    await expect.poll(
      async () => {
        const afterFlowId = new URL(loginPageA.url()).searchParams.get('flow');
        if (!afterFlowId) return -1;
        const afterResp = await contextA.request.get(
          `${baseURL}/self-service/settings/flows?id=${afterFlowId}`,
          { headers: { Accept: 'application/json' } },
        );
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const f: any = await afterResp.json();
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return (f?.ui?.nodes ?? []).filter((n: any) => n.group === 'passkey' && n.attributes?.name === 'passkey_remove').length;
      },
      { timeout: 10_000, message: 'P3: settings flow must list exactly one remaining passkey after self-removal' },
    ).toBe(1);

    const sessionB = await passkeyLogin(loginPageB, contextB, baseURL, 'P3-B');
    expect(sessionB, 'P3: passkey B must be locked out after self-removal').toBeNull();

    await clearSession(contextA, baseURL);
    const sessionA = await passkeyLogin(loginPageA, contextA, baseURL, 'P3-A');
    expect(sessionA?.active, 'P3: passkey A must still work — eviction must not be scorched-earth').toBe(true);

    await closeDevices(devA, devB);
  });
});
