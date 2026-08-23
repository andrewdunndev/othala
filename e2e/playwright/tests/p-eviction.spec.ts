/**
 * P — Lost-device / credential eviction (HIGH-C finding).
 *
 * Finding reference: HIGH-C
 *   "Session revocation does not remove passkey credentials. An attacker
 *    who obtains device B credentials can log in indefinitely even after
 *    the victim triggers force-logout via revokeSubject. The admin UI has
 *    no delete-credential path."
 *
 * Canonical model (issue #10): the admin credential-delete endpoint
 * (DELETE .../credentials/{type}) works for webauthn/totp/lookup_secret but
 * is UPSTREAM-IMPOSSIBLE for passkey — Kratos v26.2.0 identity/handler.go
 * deleteIdentityCredentials has no passkey case; it falls to default: and
 * unconditionally 400s (confirmed against the pinned v26.2.0 tag and
 * master; no issue tracks it). EVICTABLE_CREDENTIAL_TYPES (admin-api.ts)
 * no longer offers it. The canonical passkey eviction is SELF-SERVICE:
 * passkey_settings.go renders one passkey_remove node per credential
 * (settings.astro / FlowNodes group="passkey"); the victim removes the
 * lost device's key by hand. P3 proves both halves: the admin 400, then
 * the real per-credential removal end-to-end.
 *
 * P1-P3 share state (one identity, two browser contexts each with its own
 * CDP virtual authenticator) across module-scoped variables below — they run
 * serially in one worker (playwright.config.ts workers: 1, and this describe
 * block is .serial so a mid-chain failure retries the whole chain rather than
 * skip-greening). Running a subset via --grep still skips gracefully
 * (test.skip) rather than reporting a false pass.
 *
 *   P1. Seed a victim identity (unique per run); the victim enrolls passkey
 *       A in ctx-A and passkey B in ctx-B — a second browser context with
 *       its own CDP virtual authenticator, simulating a second device (lost,
 *       or an attacker who briefly had the account enrolling its own key)
 *       under the SAME identity. Both sessions are cleared afterward.
 *   P2. Admin calls the revoke-user admin endpoint (force-logout fan-out to
 *       Kratos + Hydra — same endpoint smoke.sh Section E drives). Passkey B
 *       can STILL log in afterward — revoke does not remove credentials.
 *   P3. (a) The admin credential-delete endpoint 400s on type=passkey —
 *       documented, not worked around. (b) The victim (ctx-A) logs in,
 *       opens /auth/settings, and self-removes passkey B via its rendered
 *       passkey_remove control. (c) Passkey B is locked out. (d) Passkey A
 *       still works — eviction is targeted, not scorched-earth.
 *
 * Live-stack requirements:
 *   - Kratos passkey strategy enabled, rp.id = othala.test.
 *   - Chromium (CDP required for virtual authenticators).
 *   - Playwright container on the compose net.
 *   - P2 needs OTHALA_ADMIN_ENDPOINT_BEARER (e2e/compose.yml playwright
 *     service) to call {OTHALA_ADMIN_URL}/admin/revoke-user — the loopback
 *     admin port, reachable from the playwright container only because the
 *     browser profile binds it to othala's static IP (compose.browser.yml),
 *     not 127.0.0.1. NOT {baseURL}/admin/api/revoke — that path doesn't
 *     exist; the admin surface is never routed through the public Caddy edge.
 *
 * Status (issue #10, RESOLVED): P1-P3 all run against the canonical model.
 * ctx-A is now manually created (browser.newContext(), same as ctx-B) rather
 * than sourced from the test-scoped `page`/`virtualAuthenticator` fixtures,
 * which Playwright tears down at the end of P1 — P3 needs ctx-A alive to
 * prove passkey A survives. P2/P3 share I1's usernameless-login leg
 * (passkeyLogin() below) — the prior "session null after click" symptom was
 * a harness race (networkidle satisfied mid-ceremony by the CDP virtual
 * authenticator's zero-network-traffic resolve, before the session cookie
 * landed), fixed by waiting on navigation instead.
 */

import { test, expect } from '../fixtures';
import type { BrowserContext, CDPSession, Page } from 'playwright-core';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';
import { capturePasskeyLoginDiagnostics, probePasskeyLoginCapabilities } from '../actions/diagnostics';

const PASSKEY_REGISTER_BUTTON = 'button[name="passkey_register_trigger"]';
const PASSKEY_LOGIN_BUTTON = 'button[name="passkey_login_trigger"]';

// Helper: register a passkey for `identity` using the provided page (whose
// context has a virtual authenticator attached via CDP). Requires the page's
// context to already hold an active privileged session cookie.
async function registerPasskeyForContext(
  page: Page,
  baseURL: string,
  identity: { id: string; email: string },
): Promise<void> {
  await page.goto(`${baseURL}/auth/settings`);
  await page.waitForLoadState('networkidle');
  const btn = page.locator(PASSKEY_REGISTER_BUTTON).first();
  await expect(btn, 'passkey register button must be visible').toBeVisible({ timeout: 10_000 });
  // Same race as I1: the trigger's onclick glue is a bottom-of-page <script>
  // node; wait for it to exist before a synthetic click.
  await page.waitForFunction(() => typeof (window as unknown as Record<string, unknown>).oryPasskeySettingsRegistration === 'function');
  await btn.click();
  await page.waitForLoadState('networkidle');
  console.log(`[P] passkey registered for ${identity.email} at URL:`, page.url());
}

// Helper: attempt a usernameless passkey login on `page` and return the
// resulting session (null if login failed). `page` must already carry a CDP
// virtual authenticator (WebAuthn.enable is per-target — see I1's docblock
// note — so a fresh page here would have none to intercept credentials.get()).
async function passkeyLogin(page: Page, ctx: BrowserContext, baseURL: string, label: string) {
  await page.goto(`${baseURL}/auth/login`);
  await page.waitForLoadState('networkidle');
  console.log(`[${label}] login-page capability probe:`, JSON.stringify(await probePasskeyLoginCapabilities(page)));

  let loginBtn = page.locator(PASSKEY_LOGIN_BUTTON).first();
  // Observed flaky (i-passkey-register-login.spec.ts I1): the trigger node
  // is occasionally absent from the first SSR response after a fresh
  // navigation; a reload consistently renders it. One reload, not a longer
  // timeout: a hung render doesn't resolve by waiting.
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
  // Deterministic wait (work item #8 root cause, same as I1): the CDP
  // virtual authenticator resolves credentials.get() with ZERO network
  // traffic, so networkidle was satisfied before Kratos's follow-up POST +
  // redirect landed the session cookie. Wait on the actual navigation
  // instead — bounded, and tolerant of the P3 case where login is
  // EXPECTED to fail (no redirect ever happens there; the caller's own
  // assertion on the returned session proves that outcome, not this wait).
  await page.waitForURL((u) => !u.pathname.startsWith('/auth/login'), { timeout: 15_000 }).catch(() => {});
  return getSession(ctx, baseURL);
}

// Helper: clear the session from a browser context (logout + cookie clear).
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

// ── Module-scoped state shared across P1 → P2 → P3 (see file docblock) ──────
let sharedIdentity: { id: string; email: string } | null = null;
let ctxA: BrowserContext | null = null;
let pageA: Page | null = null;
let cdpA: CDPSession | null = null;
let authenticatorIdA = '';
let ctxB: BrowserContext | null = null;
let pageB: Page | null = null;
let cdpB: CDPSession | null = null;
let authenticatorIdB = '';

// Helper: manually stand up a browser context with its own CDP virtual
// authenticator — the fixtures/index.ts `virtualAuthenticator` fixture is
// test-scoped (torn down at the end of whichever test declares it), so both
// devices need this done by hand to survive from P1 into P3.
async function newDeviceContext(browser: import('playwright-core').Browser) {
  const ctx = await browser.newContext();
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

test.describe.serial('P — Passkey credential eviction (lost-device scenario)', () => {
  test.afterAll(async () => {
    if (ctxA) await ctxA.close().catch(() => {});
    if (ctxB) await ctxB.close().catch(() => {});
  });

  test('P1 — victim enrolls passkey A; a second context enrolls passkey B', async ({
    browser,
    baseURL,
    kratosAdminURL,
  }) => {
    // Unique per run: a fixed email is 409-idempotent in createIdentityWithPassword,
    // which reuses the SAME identity across runs and accretes stray credentials
    // (webauthn:1 observed) rather than giving each run a clean slate.
    const uniqueSuffix = Date.now();
    const identity = await createIdentityWithPassword({
      email: `evict.victim.${uniqueSuffix}@othala.test`,
      username: `evict.victim.${uniqueSuffix}`,
      displayName: 'Eviction Victim',
      groups: [],
      kratosAdminURL,
    });
    console.log('[P1] seeded identity:', identity.id);

    // ctx-A: device 1. Login + register passkey A.
    const devA = await newDeviceContext(browser);
    ctxA = devA.ctx;
    pageA = devA.page;
    cdpA = devA.cdp;
    authenticatorIdA = devA.authenticatorId;
    await loginViaJsonApi(ctxA, { identifier: identity.email, password: TEST_PASSWORD }, baseURL);
    await registerPasskeyForContext(pageA, baseURL, identity);

    // ctx-B: device 2, under the SAME identity (a second device — lost, or
    // an attacker who briefly had the account, enrolling its own key).
    const devB = await newDeviceContext(browser);
    ctxB = devB.ctx;
    pageB = devB.page;
    cdpB = devB.cdp;
    authenticatorIdB = devB.authenticatorId;
    console.log('[P1] second virtual authenticator id:', authenticatorIdB);

    await loginViaJsonApi(ctxB, { identifier: identity.email, password: TEST_PASSWORD }, baseURL);
    await registerPasskeyForContext(pageB, baseURL, identity);

    // Server-side proof both passkeys were persisted. Poll — same race
    // class as #8/I1: the second ceremony's CDP resolve can return before
    // Kratos finishes writing that credential.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let registered: any;
    await expect.poll(
      async () => {
        registered = await fetch(`${kratosAdminURL}/admin/identities/${identity.id}`).then((r) => r.json());
        return registered?.credentials?.passkey;
      },
      { timeout: 10_000, message: 'P1: identity must have passkey credentials after both enrollments' },
    ).toBeTruthy();
    console.log('[P1] passkey credential record:', JSON.stringify(registered?.credentials?.passkey));

    // Clear both sessions — P2's "still works after revoke" assertion needs
    // a FRESH login, not a residual cookie.
    await clearSession(ctxA, baseURL);
    await clearSession(ctxB, baseURL);

    sharedIdentity = identity;
  });

  // P2 shares I1's usernameless-login leg (passkeyLogin() above); resolved
  // per the file docblock Status note — was a networkidle wait race, not a
  // product bug.
  test('P2 — admin revokeSubject force-logout; passkey B can STILL log in (documents the gap)', async ({ baseURL }) => {
    if (!sharedIdentity || !ctxB || !pageB) {
      test.skip(true, 'P2: requires P1 to have run first in this worker (shared module state)');
      return;
    }
    const identity = sharedIdentity;
    const contextB = ctxB;
    const loginPageB = pageB;
    const bearer = process.env.OTHALA_ADMIN_ENDPOINT_BEARER;
    if (!bearer) {
      test.skip(true, 'P2: OTHALA_ADMIN_ENDPOINT_BEARER not set — compose.yml playwright service env');
      return;
    }
    const adminBase = process.env.OTHALA_ADMIN_URL ?? 'http://othala:4431';

    const revokeResp = await fetch(`${adminBase}/admin/revoke-user`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` },
      body: JSON.stringify({ subject: identity.id }),
    });
    expect(revokeResp.ok, 'P2: revoke-user call must succeed').toBe(true);
    console.log('[P2] revoke-user response:', await revokeResp.text());

    const session = await passkeyLogin(loginPageB, contextB, baseURL, 'P2');
    expect(session?.active, 'P2: passkey B must STILL work after revoke (documents the gap)').toBe(true);
  });

  // P3 shares I1's usernameless-login leg (passkeyLogin() above); resolved
  // per the file docblock Status note — was a networkidle wait race, not a
  // product bug.
  test('P3 — victim self-removes the lost passkey; B locked out, A survives', async ({ baseURL, kratosAdminURL }) => {
    if (!sharedIdentity || !ctxA || !pageA || !ctxB || !pageB) {
      test.skip(true, 'P3: requires P1 to have run first in this worker (shared module state)');
      return;
    }
    const identity = sharedIdentity;
    const contextA = ctxA;
    const loginPageA = pageA;
    const contextB = ctxB;
    const loginPageB = pageB;

    // Log out ctx-B first: a fresh login attempt is what proves the
    // credential is gone, not just that P2's issued session still works.
    await clearSession(contextB, baseURL);

    // (a) The upstream limitation, documented rather than worked around:
    // Kratos v26.2.0 identity/handler.go deleteIdentityCredentials has no
    // `passkey` case in its switch — it falls to default: and unconditionally
    // 400s (confirmed against the pinned v26.2.0 tag AND master; no upstream
    // issue tracks it — see issue #10). This is why EVICTABLE_CREDENTIAL_TYPES
    // (admin-api.ts) no longer offers passkey.
    const adminDeleteResp = await fetch(
      `${kratosAdminURL}/admin/identities/${identity.id}/credentials/passkey`,
      { method: 'DELETE' },
    );
    const adminDeleteBody = await adminDeleteResp.text().catch(() => '');
    expect(adminDeleteResp.status, 'P3a: admin credential-type DELETE must document the upstream refusal').toBe(400);
    expect(adminDeleteBody, 'P3a: refusal reason must name the passkey type').toContain('Credentials type passkey cannot be deleted.');

    // (b) The CANONICAL eviction: the victim (ctx-A, still holding passkey A
    // + password) logs in and self-removes passkey B via the rendered
    // passkey_remove control (settings.astro / FlowNodes group="passkey").
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
    // Each passkey_remove node's `value` is the credential ID (hex —
    // x/webauthnx/nodes.go NewPasskeyUnlink); its meta.label.context.added_at_unix
    // is the enrollment time (text.NewInfoSelfServiceRemovePasskey). Both
    // buttons render identical label text ("Remove passkey \"unnamed\"") since
    // neither ceremony sets a display name, so the credential ID + added_at
    // in the node's own attributes — not the label — is what distinguishes
    // them. Passkey B is whichever node was enrolled LATER (ctx-B, in P1).
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

    const removeBtn = loginPageA.locator(`button[name="passkey_remove"][value="${passkeyBCredentialId}"]`);
    await expect(removeBtn, 'P3: passkey B remove button must be visible').toBeVisible({ timeout: 10_000 });
    await removeBtn.click();
    await loginPageA.waitForLoadState('networkidle');

    // Server-side proof the removal landed, via the same self-service surface
    // — same race class as P1: a premature login attempt would prove nothing.
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

    // (c) Passkey B is locked out — targeted eviction worked.
    const sessionB = await passkeyLogin(loginPageB, contextB, baseURL, 'P3-B');
    expect(sessionB, 'P3: passkey B must be locked out after self-removal').toBeNull();

    // (d) Passkey A still works — eviction is targeted, not scorched-earth.
    await clearSession(contextA, baseURL);
    const sessionA = await passkeyLogin(loginPageA, contextA, baseURL, 'P3-A');
    expect(sessionA?.active, 'P3: passkey A must still work — eviction must not be scorched-earth').toBe(true);

    if (cdpA) {
      await cdpA.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: authenticatorIdA }).catch(() => {});
      await cdpA.detach().catch(() => {});
    }
    if (cdpB) {
      await cdpB.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: authenticatorIdB }).catch(() => {});
      await cdpB.detach().catch(() => {});
    }
  });
});
