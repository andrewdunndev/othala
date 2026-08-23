/**
 * I — Passkey register → usernameless login (CDP virtual authenticator).
 *
 * Coverage gap addressed: the PRIMARY login method (passkey) had ZERO e2e
 * coverage. This spec proves the full discoverable-credential path end-to-end:
 *   1. Seed a fresh identity via the Kratos admin API.
 *   2. Log in with password to obtain a privileged session (required for
 *      the /auth/settings flow — Kratos enforces privileged_session_max_age).
 *   3. Register a passkey via the Kratos settings flow, backed by the CDP
 *      virtual CTAP2 authenticator. The authenticator intercepts the
 *      navigator.credentials.create() call and produces a synthetic
 *      discoverable credential (resident key, UV always passes).
 *   4. Log OUT (clear the session so there is no residual cookie).
 *   5. Navigate to the login page and trigger the USERNAMELESS passkey
 *      button — no identifier field typed. The authenticator intercepts
 *      navigator.credentials.get() and returns the stored resident key.
 *   6. Assert an active session is established via /sessions/whoami and
 *      that the session identity matches the seeded identity.
 *
 * Why this is hard to test otherwise:
 *   - Real passkeys require a hardware authenticator or the OS credential
 *     manager. CDP's WebAuthn.addVirtualAuthenticator gives us a software
 *     authenticator that is indistinguishable to the browser/Kratos.
 *   - The usernameless (discoverable credential) path is the SPECIFIC
 *     behaviour Kratos's `passkey` strategy (not the legacy `webauthn`
 *     strategy) enables. This is the path family members actually use.
 *
 * Virtual authenticator fixture (from fixtures/index.ts, ported from Ory
 * upstream test/e2e/playwright/fixtures/index.ts):
 *   - protocol: ctap2
 *   - transport: internal  (platform authenticator → triggers conditional UI)
 *   - hasResidentKey: true (discoverable credentials)
 *   - hasUserVerification: true + isUserVerified: true (UV always passes)
 *
 * Live-stack requirements:
 *   - Kratos passkey strategy enabled + rp.id = othala.test,
 *     rp.origins = http://auth.othala.test (set in gen-secrets.sh / compose env).
 *   - The browser profile (compose `browser` profile) must be up.
 *   - Tests run inside the compose net (the playwright container is on the
 *     same network as kratos, so kratosAdminURL http://kratos:4434 is reachable).
 *   - Chromium only — CDP is not available on Firefox/WebKit.
 */

import { test, expect } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';
import { capturePasskeyLoginDiagnostics, probePasskeyLoginCapabilities } from '../actions/diagnostics';

// The passkey settings page selector for the "Add a passkey" / "Register" trigger.
// Kratos renders a button node with name="passkey_register_trigger" for the
// passkey registration action on the settings UI (Kratos ui/node/identifiers.go
// PasskeyRegisterTrigger = "passkey_register_trigger").
const PASSKEY_REGISTER_BUTTON = 'button[name="passkey_register_trigger"]';

// Login page selector for the "Sign in with a passkey" trigger (the usernameless
// path). Kratos renders this as a button node with name="passkey_login_trigger"
// (Kratos passkey_login.go, PasskeyLoginTrigger = "passkey_login_trigger").
// This is distinct from the hidden passkey_login field used for autocomplete init.
const PASSKEY_LOGIN_BUTTON = 'button[name="passkey_login_trigger"]';

test.describe('I — Passkey register → usernameless login', () => {
  // I1 status (work item #8, RESOLVED): the button-visibility bug
  // (login.astro's webauthn glue-script node miscounted as a second
  // factor) and the playwright.config.ts channel:'chromium' headless-shell
  // flag bug are both fixed and proven. The remaining "session null after
  // click" symptom was a harness race, not a product bug: the CDP virtual
  // authenticator resolves navigator.credentials.get() with zero network
  // traffic, so networkidle was satisfied mid-ceremony, before Kratos's
  // follow-up POST + redirect landed the session cookie — fixed below by
  // waiting on the actual navigation instead of networkidle.
  test('I1 — register a passkey via settings, then log in usernameless', async ({
    browser,
    baseURL,
    kratosAdminURL,
    page,
    virtualAuthenticator,
  }) => {
    // The virtualAuthenticator fixture is already set up when this test runs.
    // CDP WebAuthn domain is enabled, a CTAP2 platform authenticator with
    // resident keys is active. Any credentials.create/get call on this page
    // will be intercepted by the virtual authenticator.
    console.log('[I1] virtual authenticator id:', virtualAuthenticator.authenticatorId);

    // Surface browser-side failures directly — a WebAuthn ceremony that
    // throws (e.g. an RP ID mismatch) fails inside page JS and would
    // otherwise only show up as Kratos silently not persisting a
    // credential, with nothing in the test log to explain why.
    page.on('pageerror', (err) => console.log('[I1] page error:', err.message));

    // Step 1: Seed a fresh identity for this spec (unique localpart to avoid
    // conflicts with the shared `member`/`admin` worker-scoped fixtures).
    const identity = await createIdentityWithPassword({
      email: 'passkey.tester@othala.test',
      username: 'passkey.tester',
      displayName: 'Passkey Tester',
      groups: [],
      kratosAdminURL,
    });
    console.log('[I1] seeded identity:', identity.id, identity.email);

    // Step 2: Obtain a privileged session. Kratos requires a privileged session
    // (within privileged_session_max_age: 15m) for the settings flow. Log in via
    // the JSON-API path to set the session cookie in the BrowserContext, then
    // navigate to /auth/settings on the live page (same context = same cookie jar).
    const ctx = page.context();
    await loginViaJsonApi(ctx, { identifier: identity.email, password: TEST_PASSWORD }, baseURL);

    const session = await getSession(ctx, baseURL);
    expect(session?.active, 'I1 precondition: must have active session before passkey registration').toBe(true);
    expect(session?.identity?.traits?.email).toBe(identity.email);
    console.log('[I1] session established, AAL:', session?.authenticator_assurance_level);

    // Step 3: Navigate to the settings page to register the passkey.
    // The virtual authenticator is attached to `page` (via pageCDPSession on the
    // same page). Kratos will call navigator.credentials.create(); the CDP
    // virtual authenticator intercepts and produces a resident credential.
    await page.goto(`${baseURL}/auth/settings`);
    await page.waitForLoadState('networkidle');

    // Click the passkey registration trigger. Kratos renders a button with
    // name="passkey_register_trigger" (identifiers.go PasskeyRegisterTrigger).
    // After clicking, the browser calls credentials.create() — the virtual
    // authenticator responds with a synthetic credential, Kratos stores it,
    // and the page reloads showing success.
    const registerBtn = page.locator(PASSKEY_REGISTER_BUTTON).first();
    await expect(registerBtn, 'I1: passkey register button must be visible on settings page').toBeVisible({ timeout: 10_000 });
    // The button's onclick calls window.oryPasskeySettingsRegistration(), but
    // that glue is defined by a <script> node rendered at the page bottom
    // (settings.astro scriptNodes) — a real page load wins that race, a
    // synthetic click the instant the button exists does not. Wait for the
    // function to actually exist before clicking.
    await page.waitForFunction(() => typeof (window as unknown as Record<string, unknown>).oryPasskeySettingsRegistration === 'function');
    await registerBtn.click();

    // Wait for Kratos to confirm the registration. The settings page will show
    // a success message or re-render the passkey list with the new entry.
    // A page reload to networkidle is a safe wait; the Kratos settings flow
    // POSTs and redirects back to /auth/settings on success.
    await page.waitForLoadState('networkidle');
    console.log('[I1] passkey registered, current URL:', page.url());

    // Assert no error on the settings page after registration.
    const pageText = await page.textContent('body');
    expect(
      pageText,
      'I1: settings page must not show an error after passkey registration',
    ).not.toMatch(/error|something went wrong/i);

    // Server-side proof the credential was actually persisted — the page
    // check above would also pass if credentials.create() silently no-op'd.
    // No credentials.passkey entry exists on the identity until a passkey is
    // registered (the seed body only set credentials.password), so presence
    // alone is the non-vacuous signal. Poll rather than a single read: same
    // race class as #8's login-leg fix — the CDP-resolved ceremony can
    // return before Kratos finishes writing the credential.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let registered: any;
    await expect.poll(
      async () => {
        registered = await fetch(`${kratosAdminURL}/admin/identities/${identity.id}`).then((r) => r.json());
        return registered?.credentials?.passkey;
      },
      { timeout: 10_000, message: 'I1: identity must have a passkey credential recorded server-side after registration' },
    ).toBeTruthy();
    console.log('[I1] passkey credential record:', JSON.stringify(registered?.credentials?.passkey));

    // Step 4: Log out to clear the session. We need a clean state for the
    // usernameless login assertion to prove the passkey is genuinely usable
    // (not just that the settings page accepted it while a session existed).
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
    // Clear cookies directly as a belt-and-suspenders guarantee.
    await ctx.clearCookies();

    // Confirm no session.
    const afterLogout = await getSession(ctx, baseURL);
    expect(
      afterLogout,
      'I1 precondition (post-logout): session must be gone before usernameless login',
    ).toBeNull();

    // Step 5: Usernameless login via the passkey button. REUSES `page` — the
    // CDP virtual authenticator is scoped to the specific page/session that
    // added it (WebAuthn.enable is per-target, confirmed by P1's ctx-B
    // needing its own CDP session for a second page); a fresh page here has
    // no authenticator to intercept credentials.get() at all. An earlier
    // revision tried a fresh page anyway (chasing a client-capability
    // hypothesis the probe below had already disproven) and broke the
    // ceremony — reverted.
    await page.goto(`${baseURL}/auth/login`);
    await page.waitForLoadState('networkidle');

    // Capability probe: the button is a SERVER-rendered node (login.astro
    // renders it iff Kratos's flow.ui.nodes has a `passkey` group — see
    // hasMethod() in lib/nodes.ts), not something client JS shows or hides.
    // If conditional mediation / the trigger glue is missing, the fault is
    // upstream of anything this page can retry into existing.
    console.log('[I1] login-page capability probe:', JSON.stringify(await probePasskeyLoginCapabilities(page)));

    let loginBtn = page.locator(PASSKEY_LOGIN_BUTTON).first();
    // Observed flaky: the trigger node is occasionally absent from the first
    // SSR response after a fresh navigation (unrelated to the credential —
    // a reload re-requests the login flow and consistently renders it). One
    // reload, not a longer timeout: a hung render doesn't resolve by waiting.
    if (!(await loginBtn.isVisible().catch(() => false))) {
      await page.reload();
      await page.waitForLoadState('networkidle');
      loginBtn = page.locator(PASSKEY_LOGIN_BUTTON).first();
    }
    if (!(await loginBtn.isVisible().catch(() => false))) {
      await capturePasskeyLoginDiagnostics(page, 'I1-login-missing');
    }
    await expect(loginBtn, 'I1: passkey login button must be visible on the login page').toBeVisible({ timeout: 10_000 });
    // Same race as registration: wait for the login trigger's glue
    // (window.oryPasskeyLogin, per KNOWN_TRIGGERS in lib/nodes.ts) to exist.
    await page.waitForFunction(() => typeof (window as unknown as Record<string, unknown>).oryPasskeyLogin === 'function');
    await loginBtn.click();

    // Deterministic wait (work item #8 root cause): the CDP virtual
    // authenticator resolves credentials.get() with ZERO network traffic,
    // so networkidle returns before Kratos's follow-up POST + redirect
    // land the session cookie. Wait for the actual navigation away from
    // /auth/login instead, then poll for the session (the cookie can land
    // a beat after the URL changes).
    await page.waitForURL((u) => !u.pathname.startsWith('/auth/login'), { timeout: 15_000 });
    console.log('[I1] post-passkey-login URL:', page.url());

    // Step 6: Verify the session. The session must be active and tied to the
    // identity we registered the passkey for.
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
