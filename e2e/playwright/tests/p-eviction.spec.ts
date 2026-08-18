/**
 * P — Lost-device / credential eviction (DESIGNED test, HIGH-C finding).
 *
 * Finding reference: HIGH-C
 *   "Session revocation does not remove passkey credentials. An attacker
 *    who obtains device B credentials can log in indefinitely even after
 *    the victim triggers force-logout via revokeSubject. The admin UI has
 *    no delete-credential path."
 *
 * Status: NOT LIVE. Every test below is test.fixme() — none run. The whole
 * describe block is fixme'd, not just the individual steps, because P1-P3
 * share state across two virtual-authenticator contexts and only make sense
 * run together against the live compose stack; splitting the fixme finer
 * would let a partial run report a false pass. The structure still PARSES
 * cleanly under `playwright test --list`, so this file documents the
 * intended coverage without claiming to exercise it.
 *
 * Scenario order (P1-P3) proves the FINDING, and deliberately does not match
 * the recommended admin sequence. P2 revokes before P3 deletes, to show that
 * revoke-first leaves the attacker's credential live — that is the bug. The
 * correct operator order is the opposite: audit credentials, delete the
 * affected type, THEN revoke (`docs/runbooks/lost-device.md`), because
 * revoking first burns the session before you can see what needs auditing.
 *
 *   P1. Seed a victim identity; victim enrolls passkey A in
 *       virtual-authenticator ctx-A; a thief enrolls passkey B in a second
 *       virtual-authenticator ctx-B (simulates hijack or co-enrollment).
 *   P2. Admin calls revokeSubject (force-logout). Passkey B can STILL log
 *       in afterward — revoke does not remove credentials.
 *   P3. Admin calls the Kratos admin delete-credential API to remove
 *       passkey B; B is then locked out (login fails, no session issued).
 *
 * Live-stack requirements once un-fixme'd:
 *   - Kratos passkey strategy enabled, rp.id = othala.test.
 *   - Chromium (CDP required for virtual authenticators).
 *   - Playwright container on the compose net.
 *   - The othala admin revoke endpoint reachable at {baseURL}/admin/api/revoke
 *     (the existing revokeSubject handler).
 *   - P3 also needs Kratos admin DELETE
 *     /admin/identities/{id}/credentials/{type} plumbed through the admin
 *     UI (TODO(HIGH-C)); until then P3 stays fixme even once P1/P2 are wired.
 */

import { test, expect } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';

const PASSKEY_REGISTER_BUTTON = 'button[name="passkey_register_trigger"]';
const PASSKEY_LOGIN_BUTTON = 'button[name="passkey_login_trigger"]';

// Helper: register a passkey for `identity` using the provided browser context
// (which has a virtual authenticator attached via CDP).
// Requires `ctx` to already have an active privileged session cookie.
async function registerPasskeyForContext(
  page: import('@playwright/test').Page,
  baseURL: string,
  identity: { id: string; email: string },
): Promise<void> {
  await page.goto(`${baseURL}/auth/settings`);
  await page.waitForLoadState('networkidle');
  const btn = page.locator(PASSKEY_REGISTER_BUTTON).first();
  await expect(btn, 'passkey register button must be visible').toBeVisible({ timeout: 10_000 });
  await btn.click();
  await page.waitForLoadState('networkidle');
  console.log(`[P] passkey registered for ${identity.email} at URL:`, page.url());
}

// Helper: clear the session from a browser context (logout + cookie clear).
async function clearSession(
  ctx: import('@playwright/test').BrowserContext,
  baseURL: string,
): Promise<void> {
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

test.describe('P — Passkey credential eviction (lost-device scenario)', () => {
  // P1 + P2 + P3 are DESIGNED to run against the live stack and document the
  // CURRENT GAP (revoke does not remove credentials), but none run today —
  // see the file docblock's Status note.
  //
  // NOTE: P1–P3 require two independent virtual authenticators on two separate
  // browser contexts. The virtualAuthenticator fixture is test-scoped and
  // attached to `page` (one context). For a second authenticator we would need
  // a second browser.newContext() with its own CDP session. That multi-context
  // pattern is feasible but requires the live compose stack; marking the full
  // describe block as fixme below to avoid false passes outside the live gate.
  //
  // The STRUCTURE of every step is defined here so `--list` parses correctly.

  test.fixme(
    'P1 — victim enrolls passkey A; thief enrolls passkey B in a second context',
    async ({ browser, page, baseURL, kratosAdminURL, virtualAuthenticator }) => {
      // TODO(HIGH-C): implement full multi-context
      // passkey enrollment. Requires two CDP sessions (one per virtual authenticator)
      // and the live compose stack.
      //
      // Sketch:
      //   1. seed victim identity
      //   2. login in ctx-A (page.context()), register passkey A via virtualAuthenticator
      //   3. open ctx-B = browser.newContext(); attach CDP; add second virtual authenticator
      //   4. login in ctx-B with same credentials, register passkey B
      //   5. clear both sessions
      void virtualAuthenticator; // fixture referenced to satisfy the fixture dependency graph

      const identity = await createIdentityWithPassword({
        email: 'evict.victim@othala.test',
        username: 'evict.victim',
        displayName: 'Eviction Victim',
        groups: [],
        kratosAdminURL,
      });
      console.log('[P1] seeded identity:', identity.id);

      // Login in ctx-A and register passkey A.
      const ctxA = page.context();
      await loginViaJsonApi(ctxA, { identifier: identity.email, password: TEST_PASSWORD }, baseURL);
      await registerPasskeyForContext(page, baseURL, identity);
      // P1 is fixme — stop here until multi-context is wired.
    },
  );

  test.fixme(
    'P2 — admin revokeSubject force-logout; passkey B can STILL log in (documents the gap)',
    async ({ browser, page, baseURL, kratosAdminURL }) => {
      // TODO(HIGH-C): after P1 enrolls passkey B,
      // call revokeSubject on the victim's identity and then attempt login with
      // ctx-B's passkey credential. The login MUST SUCCEED (proves the gap):
      //
      //   const revokeResp = await page.context().request.post(
      //     `${baseURL}/admin/api/revoke`,
      //     { data: { subject: identity.id } },
      //   );
      //   expect(revokeResp.ok()).toBe(true);
      //
      //   // Navigate to login page in ctx-B and assert passkey login succeeds.
      //   await pageB.goto(`${baseURL}/auth/login`);
      //   const loginBtn = pageB.locator(PASSKEY_LOGIN_BUTTON).first();
      //   await loginBtn.click();
      //   await pageB.waitForLoadState('networkidle');
      //   const session = await getSession(ctxB, baseURL);
      //   expect(session?.active, 'P2: passkey B must STILL work after revoke (gap)').toBe(true);
      void browser; void page; void baseURL; void kratosAdminURL;
    },
  );

  test.fixme(
    'P3 — admin deletes credential B via Kratos admin API; passkey B is locked out (post-fix)',
    async ({ browser, page, baseURL, kratosAdminURL }) => {
      // TODO(HIGH-C): implement admin
      // DELETE /admin/identities/{id}/credentials/passkey (or the equivalent
      // per-credential endpoint once the admin UI ships the delete path).
      //
      // Kratos admin endpoint (v0.13+):
      //   DELETE {kratosAdminURL}/admin/identities/{identityId}/credentials/{type}
      //   where {type} = "passkey" (or the credential ID if the API takes a
      //   per-credential endpoint — verify against the Kratos version in compose.yml).
      //
      // Post-delete assertion:
      //   - Attempt login with ctx-B's virtual authenticator.
      //   - credentials.get() finds no stored credential → login fails.
      //   - getSession(ctxB) must return null.
      //
      //   const deleteResp = await fetch(
      //     `${kratosAdminURL}/admin/identities/${identity.id}/credentials/passkey`,
      //     { method: 'DELETE' },
      //   );
      //   expect(deleteResp.status).toBe(204);
      //
      //   await pageB.goto(`${baseURL}/auth/login`);
      //   const loginBtn = pageB.locator(PASSKEY_LOGIN_BUTTON).first();
      //   await loginBtn.click();
      //   await pageB.waitForLoadState('networkidle');
      //   const sessionAfter = await getSession(ctxB, baseURL);
      //   expect(sessionAfter, 'P3: passkey B must be locked out after credential deletion').toBeNull();
      void browser; void page; void baseURL; void kratosAdminURL;
    },
  );
});
