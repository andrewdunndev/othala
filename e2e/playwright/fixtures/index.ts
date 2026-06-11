/**
 * fixtures/index.ts — Othala test fixtures, mirroring Ory Kratos's
 * test/e2e/playwright/fixtures pattern.
 *
 * Exposes via test.extend:
 *   baseURL              — http://auth.othala.test (the Caddy edge inside compose)
 *   kratosAdminURL       — http://kratos:4434 (admin API, reachable inside compose net)
 *   hydraPublicURL       — http://hydra:4444 (Hydra public, inside compose net)
 *   hydraAdminURL        — http://hydra:4445 (Hydra admin, inside compose net)
 *   member               — { id, email, password } seeded identity (bt2@othala.test),
 *                          access-grafana group, NOT on OTHALA_ADMIN_IDS
 *   admin                — { id, email, password } seeded identity (admin@othala.test),
 *                          ON OTHALA_ADMIN_IDS (triggers AAL2 step-up at /admin)
 *
 * Both identities are seeded ONCE per worker (scope: 'worker') so the cost is
 * paid at most once across the serial test run.
 *
 * virtualAuthenticator / pageCDPSession — test-scoped fixtures for WebAuthn
 *   passkey testing via the Chrome DevTools Protocol (CDP). Ported from Ory
 *   upstream test/e2e/playwright/fixtures/index.ts. Establishes a CDP virtual
 *   CTAP2 authenticator (internal transport, resident keys, user verification)
 *   that Kratos's passkey strategy registers and asserts against without any
 *   real hardware.
 *
 *   Upstream reference:
 *     https://github.com/ory/kratos/blob/master/test/e2e/playwright/fixtures/index.ts
 */

import { test as base } from '@playwright/test';
import type { CDPSession } from 'playwright-core';
import { createIdentityWithPassword, TEST_PASSWORD, type SeedResult } from '../actions/identity';

// CDP Protocol WebAuthn types are available via playwright-core's protocol.d.ts.
// We use inline types here to avoid importing the full Protocol namespace (which
// is an internal playwright-core detail and not part of the public API surface).
interface VirtualAuthenticatorOptions {
  protocol: string;
  transport: string;
  hasResidentKey: boolean;
  hasUserVerification: boolean;
  isUserVerified: boolean;
  automaticPresenceSimulation?: boolean;
}

export interface OthalaFixtures {
  baseURL: string;
  kratosAdminURL: string;
  hydraPublicURL: string;
  hydraAdminURL: string;
  member: SeedResult & { password: string };
  admin: SeedResult & { password: string };
  /** Override any subset of the virtual authenticator options (test-scoped). */
  virtualAuthenticatorOptions: Partial<VirtualAuthenticatorOptions>;
  /** CDP session attached to the current page (test-scoped). */
  pageCDPSession: CDPSession;
  /** CDP virtual authenticator id (test-scoped). Cleaned up after each test. */
  virtualAuthenticator: { authenticatorId: string };
}

export const test = base.extend<OthalaFixtures>({
  // URLs: read from env (injected by compose playwright service) or fall back
  // to the compose-net defaults. Tests inside the compose net can reach these
  // directly; the Playwright container is on the same compose network.
  baseURL: async ({}, use) => {
    await use(process.env.BASE ?? 'http://auth.othala.test');
  },

  // Worker-scoped: the worker-scoped `member`/`admin` fixtures depend on
  // kratosAdminURL, and a worker fixture cannot depend on a test-scoped one.
  // (Matches Ory upstream, where these URLs are worker-scoped options.)
  kratosAdminURL: [async ({}, use) => {
    await use(process.env.KRATOS_ADMIN_URL ?? 'http://kratos:4434');
  }, { scope: 'worker' }],

  hydraPublicURL: [async ({}, use) => {
    await use(process.env.HYDRA_PUBLIC_URL ?? 'http://hydra:4444');
  }, { scope: 'worker' }],

  hydraAdminURL: [async ({}, use) => {
    await use(process.env.HYDRA_ADMIN_URL ?? 'http://hydra:4445');
  }, { scope: 'worker' }],

  // member: bt2@othala.test, access-grafana + family groups. Seeded with a
  // Kratos-assigned random id, so NOT on OTHALA_ADMIN_IDS (only the admin
  // fixture's pinned 000...001 id is).
  member: [
    async ({ kratosAdminURL }, use) => {
      const result = await createIdentityWithPassword({
        email: 'bt2@othala.test',
        username: 'bt2',
        displayName: 'Browser Test 2',
        groups: ['family', 'access-grafana'],
        kratosAdminURL,
      });
      await use({ ...result, password: TEST_PASSWORD });
    },
    { scope: 'worker' },
  ],

  // admin: seeded with the fixed identity UUID on OTHALA_ADMIN_IDS in
  // gen-secrets.sh (CVP-P1: admin authority is keyed on the immutable id, not
  // the email trait). The admin gate (requireAdminSession) checks that list by
  // id. At AAL1 (password only), visiting /admin triggers the AAL2 step-up.
  admin: [
    async ({ kratosAdminURL }, use) => {
      const result = await createIdentityWithPassword({
        // Keep in sync with OTHALA_ADMIN_IDS in e2e/gen-secrets.sh.
        id: '00000000-0000-0000-0000-000000000001',
        email: 'admin@othala.test',
        username: 'admin',
        displayName: 'Othala Admin',
        groups: ['family', 'access-grafana', 'admin'],
        kratosAdminURL,
      });
      await use({ ...result, password: TEST_PASSWORD });
    },
    { scope: 'worker' },
  ],

  // ── WebAuthn / Passkey virtual authenticator fixtures ─────────────────────
  // All three are test-scoped (one instance per test, no cross-test state).
  // Ported from Ory upstream test/e2e/playwright/fixtures/index.ts.

  // virtualAuthenticatorOptions: tests can override individual fields by
  // declaring this fixture. Default is undefined (the virtualAuthenticator
  // fixture applies its own base defaults and then spreads this on top).
  virtualAuthenticatorOptions: async ({}, use) => {
    await use({});
  },

  // pageCDPSession: opens a CDP session on the current page. Detached after
  // each test. Requires a Chromium-family browser (all our tests use chromium).
  pageCDPSession: async ({ page }, use) => {
    const cdpSession = await page.context().newCDPSession(page);
    await use(cdpSession);
    await cdpSession.detach();
  },

  // virtualAuthenticator: enables the WebAuthn CDP domain and registers a
  // software CTAP2 authenticator with resident keys + user verification
  // (the configuration Kratos passkey strategy requires for discoverable /
  // usernameless credentials). Removed + disabled after each test.
  //
  // Options match Ory upstream exactly:
  //   protocol: "ctap2"          — FIDO2 / WebAuthn Level 2
  //   transport: "internal"      — platform authenticator (triggers conditional UI)
  //   hasResidentKey: true       — discoverable credentials (required for passkeys)
  //   hasUserVerification: true  — authenticator supports UV
  //   isUserVerified: true       — UV always passes (no PIN prompt in tests)
  virtualAuthenticator: async ({ pageCDPSession, virtualAuthenticatorOptions }, use) => {
    await pageCDPSession.send('WebAuthn.enable', { enableUI: false });
    const { authenticatorId } = await pageCDPSession.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        ...virtualAuthenticatorOptions,
      },
    });
    await use({ authenticatorId });
    await pageCDPSession.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
    await pageCDPSession.send('WebAuthn.disable');
  },
});

export { expect } from '@playwright/test';
