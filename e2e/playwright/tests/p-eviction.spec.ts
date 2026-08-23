/**
 * P — Lost-device / credential eviction (HIGH-C finding).
 *
 * Finding reference: HIGH-C
 *   "Session revocation does not remove passkey credentials. An attacker
 *    who obtains device B credentials can log in indefinitely even after
 *    the victim triggers force-logout via revokeSubject. The admin UI has
 *    no delete-credential path."
 *
 * That last sentence is now STALE: deleteCredential IS wired into the admin
 * UI (portal/src/lib/admin-actions.ts removeCredentialAction, the
 * 'remove-credential' form action on /admin/users/[id].astro; unit-tested in
 * admin-actions.test.ts). P3 below drives the same Kratos admin endpoint
 * that action calls, proving the eviction primitive end-to-end against the
 * live stack rather than re-testing the already-covered portal wiring.
 *
 * P1-P3 share state (one identity, one second browser context with its own
 * CDP virtual authenticator) across module-scoped variables below — they run
 * serially in one worker (playwright.config.ts workers: 1) and only prove
 * the finding run together. Running a subset via --grep skips gracefully
 * (test.skip) rather than reporting a false pass.
 *
 *   P1. Seed a victim identity; the victim enrolls passkey A in ctx-A (the
 *       test's own page/virtualAuthenticator); a second context ctx-B with
 *       its own CDP virtual authenticator enrolls passkey B under the SAME
 *       identity (simulates a second device — lost, or an attacker who
 *       briefly had the account — enrolling its own key). Both sessions are
 *       cleared afterward.
 *   P2. Admin calls the revoke-user admin endpoint (force-logout fan-out to
 *       Kratos + Hydra — same endpoint smoke.sh Section E drives). Passkey B
 *       can STILL log in afterward — revoke does not remove credentials.
 *   P3. Admin calls the Kratos admin credential-delete endpoint to remove
 *       the identity's passkey credentials; passkey B is then locked out
 *       (login fails, no session issued).
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
 * Status (work item #8, RESOLVED): P1-P3 all run. P2/P3 share I1's
 * usernameless-login leg (passkeyLogin() below) — the prior "session null
 * after click" symptom was a harness race (networkidle satisfied mid-
 * ceremony by the CDP virtual authenticator's zero-network-traffic resolve,
 * before the session cookie landed), fixed by waiting on navigation instead.
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
let ctxB: BrowserContext | null = null;
let pageB: Page | null = null;
let cdpB: CDPSession | null = null;
let authenticatorIdB = '';

test.describe('P — Passkey credential eviction (lost-device scenario)', () => {
  test.afterAll(async () => {
    if (ctxB) await ctxB.close().catch(() => {});
  });

  test('P1 — victim enrolls passkey A; a second context enrolls passkey B', async ({
    browser,
    page,
    baseURL,
    kratosAdminURL,
    virtualAuthenticator,
  }) => {
    void virtualAuthenticator; // attached to `page` by the fixture; used implicitly by ctx-A's registration

    const identity = await createIdentityWithPassword({
      email: 'evict.victim@othala.test',
      username: 'evict.victim',
      displayName: 'Eviction Victim',
      groups: [],
      kratosAdminURL,
    });
    console.log('[P1] seeded identity:', identity.id);

    // ctx-A: the test's own page/context. Login + register passkey A.
    const ctxA = page.context();
    await loginViaJsonApi(ctxA, { identifier: identity.email, password: TEST_PASSWORD }, baseURL);
    await registerPasskeyForContext(page, baseURL, identity);

    // ctx-B: a second browser context with its OWN CDP virtual authenticator
    // — the fixture's virtualAuthenticator is test-scoped to `page` (ctx-A),
    // so a second device needs its own context + CDP session.
    ctxB = await browser.newContext();
    pageB = await ctxB.newPage();
    cdpB = await ctxB.newCDPSession(pageB);
    await cdpB.send('WebAuthn.enable', { enableUI: false });
    const { authenticatorId } = await cdpB.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
      },
    });
    authenticatorIdB = authenticatorId;
    console.log('[P1] second virtual authenticator id:', authenticatorIdB);

    await loginViaJsonApi(ctxB, { identifier: identity.email, password: TEST_PASSWORD }, baseURL);
    await registerPasskeyForContext(pageB, baseURL, identity);

    // Server-side proof both passkeys were persisted.
    const registered = await fetch(`${kratosAdminURL}/admin/identities/${identity.id}`).then((r) => r.json());
    console.log('[P1] passkey credential record:', JSON.stringify(registered?.credentials?.passkey));
    expect(registered?.credentials?.passkey, 'P1: identity must have passkey credentials after both enrollments').toBeTruthy();

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
  test('P3 — admin deletes the passkey credential type; passkey B is locked out (post-fix)', async ({ baseURL, kratosAdminURL }) => {
    if (!sharedIdentity || !ctxB || !pageB) {
      test.skip(true, 'P3: requires P1 to have run first in this worker (shared module state)');
      return;
    }
    const identity = sharedIdentity;
    const contextB = ctxB;
    const loginPageB = pageB;

    // Log out first: a fresh login attempt is what proves the credential is
    // gone, not just that P2's already-issued session cookie still works.
    await clearSession(contextB, baseURL);

    // Same endpoint portal/src/lib/admin-api.ts deleteCredential() calls
    // (identityApi().deleteIdentityCredentials) — the primitive the admin
    // UI's 'remove-credential' action already wires up.
    const deleteResp = await fetch(
      `${kratosAdminURL}/admin/identities/${identity.id}/credentials/passkey`,
      { method: 'DELETE' },
    );
    expect(deleteResp.status, 'P3: credential deletion must succeed').toBe(204);

    const sessionAfter = await passkeyLogin(loginPageB, contextB, baseURL, 'P3');
    expect(sessionAfter, 'P3: passkey B must be locked out after credential deletion').toBeNull();

    if (cdpB) {
      await cdpB.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: authenticatorIdB }).catch(() => {});
      await cdpB.detach().catch(() => {});
    }
  });
});
