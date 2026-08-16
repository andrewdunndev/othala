/**
 * fixtures/index.ts — Othala test fixtures, mirroring Ory Kratos's
 * test/e2e/playwright/fixtures pattern.
 *
 * Exposes via test.extend:
 *   baseURL              — http://auth.othala.test (the Caddy edge inside compose)
 *   kratosAdminURL       — http://kratos:4434 (admin API, reachable inside compose net)
 *   hydraPublicURL       — http://hydra:4444 (Hydra public, inside compose net)
 *   hydraAdminURL        — http://hydra:4445 (Hydra admin, inside compose net)
 *   member               — { id, email, password } seeded identity (bt2@othala.test)
 *                          holding exactly ['grafana-access'] — entry to the
 *                          grafana fixture, `viewer` role, and NOT an admin
 *                          anywhere (no metadata_admin.admin marker, no
 *                          `grafana-admin` group)
 *   admin                — { id, email, password, aal2Session } identity seeded with
 *                          metadata_admin.admin=true (ADR 08 marker) by
 *                          validate.sh seed phase. The fixture looks up the id,
 *                          then performs TOTP enrollment + AAL2 step-up so that
 *                          adminWithAal2() provides an AAL2 BrowserContext ready
 *                          for /admin access.
 *
 * Both identities are seeded ONCE per worker (scope: 'worker') so the cost is
 * paid at most once across the serial test run.
 *
 * AAL2 admin access:
 *   /admin requires AAL2 (ADR 08). TOTP CANNOT be pre-seeded via the admin
 *   API — it must be enrolled via the Kratos settings flow at runtime:
 *     1. Log in as admin (password → AAL1 session).
 *     2. Initiate a settings flow, read the TOTP secret from ui.nodes
 *        (the totp group text/img nodes Kratos emits during enrollment).
 *     3. Compute a valid TOTP code from the captured secret (RFC-6238,
 *        HMAC-SHA1, 30s window, 6 digits — built-in helper below, no dep).
 *     4. Submit the TOTP confirmation code to complete enrollment.
 *     5. Initiate an AAL2 login flow (?aal=aal2), submit a fresh TOTP code.
 *        The resulting session carries AAL2 and can access /admin.
 *   adminAal2Context() encapsulates this; admin specs that need to reach /admin
 *   call it instead of loginViaJsonApi. Steps 2-4 are also available standalone
 *   as enrollTotpSecret() (returns just the secret) + computeTotp() (both
 *   exported) for specs that need to drive the AAL2 step-up themselves via a
 *   REAL browser-page navigation instead of adminAal2Context's JSON-API
 *   shortcut for step 5 — e.g. s-aal2-natural-redirect.spec.ts, which exists
 *   specifically because the JSON-API shortcut never exercises Kratos's
 *   actual redirect-drops-the-aal-param behaviour (work item #4).
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
import type { BrowserContext, CDPSession } from 'playwright-core';
import { createIdentityWithPassword, TEST_PASSWORD, type SeedResult } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';

// ── Minimal RFC-6238 TOTP implementation ─────────────────────────────────────
// Used to compute TOTP codes from the secret Kratos returns during enrollment.
// No external dependency: Node's built-in `crypto` module only.
// Algorithm: HOTP(secret, T) where T = Math.floor(Date.now() / 1000 / 30).
// secret is base32-encoded (RFC-4648, no padding required).

/** Base32 decode (RFC-4648, case-insensitive, no padding required). */
function base32Decode(input: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const str = input.toUpperCase().replace(/=+$/, '');
  let bits = 0;
  let value = 0;
  let index = 0;
  const output = new Uint8Array(Math.floor((str.length * 5) / 8));
  for (let i = 0; i < str.length; i++) {
    const idx = alphabet.indexOf(str[i]);
    if (idx === -1) continue; // skip non-alphabet chars (spaces, dashes)
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  return output.slice(0, index);
}

/**
 * Compute a 6-digit TOTP code (RFC-6238, HMAC-SHA1, 30s step).
 * @param secret  Base32-encoded TOTP secret (from Kratos settings flow).
 * @param t       Optional Unix timestamp in seconds (default: now).
 *
 * Exported so specs that need to complete their OWN AAL2 step-up (e.g. a
 * real browser-driven natural-redirect step-up, distinct from the JSON-API
 * shortcut adminAal2Context takes) can compute a fresh code without
 * duplicating the RFC-6238 implementation.
 */
export async function computeTotp(secret: string, t?: number): Promise<string> {
  const { createHmac } = await import('node:crypto');
  const keyBytes = base32Decode(secret);
  const counter = BigInt(Math.floor((t ?? Date.now() / 1000) / 30));
  // Counter as 8-byte big-endian buffer.
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(counter);
  const hmac = createHmac('sha1', Buffer.from(keyBytes));
  hmac.update(counterBuf);
  const digest = hmac.digest();
  // Dynamic truncation per RFC-4226 §5.4.
  const offset = digest[digest.length - 1] & 0x0f;
  const code =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(code % 1_000_000).padStart(6, '0');
}

/**
 * Extract a TOTP secret from a Kratos settings flow's ui.nodes.
 * Kratos emits a text node in group "totp" whose attributes.text.text is the
 * raw base32 TOTP secret when enrollment is in progress.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractTotpSecret(flowNodes: any[]): string {
  for (const node of flowNodes ?? []) {
    if (node?.group !== 'totp') continue;
    // The secret text node: type=="text" (or node_type=="text") with the secret.
    const attrs = node?.attributes;
    if (
      attrs &&
      (attrs.node_type === 'text' || node?.type === 'text') &&
      typeof attrs?.text?.text === 'string' &&
      // Kratos sets id=1050015 for the TOTP secret node.
      (attrs.text?.id === 1050015 || /^[A-Z2-7]{16,}$/i.test(attrs.text.text))
    ) {
      return attrs.text.text;
    }
  }
  return '';
}

/**
 * enrollTotpSecret — enroll TOTP for the identity already logged in on `ctx`
 * (an AAL1 session is required — Kratos's settings flow needs a privileged
 * session) and return the base32 secret so the caller can compute codes.
 *
 * Sequence:
 *   1. Initiate a Kratos settings flow (Accept: application/json).
 *   2. Read the TOTP secret from the flow's ui.nodes (totp group, text node).
 *      If Kratos doesn't return TOTP nodes immediately, submit the settings
 *      form with method=totp to trigger enrollment and re-fetch the flow.
 *   3. Compute a TOTP code from the secret and submit it to enroll TOTP.
 *
 * Factored out of adminAal2Context so any spec that needs a TOTP-enrolled
 * identity (e.g. to drive a REAL browser-page AAL2 step-up rather than the
 * JSON-API shortcut below) can reuse the exact same enrollment path.
 *
 * Throws if any step fails — a clear error message identifies which step.
 */
export async function enrollTotpSecret(
  ctx: BrowserContext,
  baseURL: string,
): Promise<string> {
  // Step 1: initiate settings flow to enroll TOTP.
  const settingsResp = await ctx.request.get(`${baseURL}/self-service/settings/browser`, {
    headers: { Accept: 'application/json' },
    maxRedirects: 5,
  });
  if (!settingsResp.ok()) {
    throw new Error(
      `enrollTotpSecret: settings flow init failed: ${settingsResp.status()}`,
    );
  }
  const settingsFlow = await settingsResp.json() as {
    id: string;
    ui: {
      action: string;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      nodes: any[];
    };
  };

  // Step 2: extract the TOTP secret. If Kratos doesn't return TOTP nodes
  // immediately, submit the settings form with method=totp to trigger
  // enrollment and re-fetch the flow.
  let totpSecret = extractTotpSecret(settingsFlow.ui?.nodes ?? []);
  let flowAction: string = settingsFlow.ui?.action ?? '';
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let flowNodes: any[] = settingsFlow.ui?.nodes ?? [];

  if (!totpSecret) {
    // Find the CSRF token from the current nodes.
    let csrfToken = '';
    for (const node of flowNodes) {
      if (
        node?.attributes?.name === 'csrf_token' &&
        node?.attributes?.type === 'hidden'
      ) {
        csrfToken = node.attributes.value ?? '';
        break;
      }
    }

    // Trigger TOTP enrollment by submitting method=totp.
    const totpTriggerResp = await ctx.request.post(flowAction, {
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      data: { csrf_token: csrfToken, method: 'totp' },
      maxRedirects: 5,
    });
    const totpFlow = await totpTriggerResp.json() as {
      ui?: {
        action?: string;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        nodes?: any[];
      };
    };
    flowNodes = totpFlow?.ui?.nodes ?? flowNodes;
    flowAction = totpFlow?.ui?.action ?? flowAction;
    totpSecret = extractTotpSecret(flowNodes);
  }

  if (!totpSecret) {
    throw new Error(
      'enrollTotpSecret: TOTP secret not found in settings flow nodes. ' +
      'Check that the TOTP strategy is enabled in kratos.yml and that the ' +
      'settings flow returns totp group nodes.',
    );
  }

  console.log('[enrollTotpSecret] TOTP secret captured (first 6 chars):', totpSecret.slice(0, 6) + '…');

  // Step 3: compute a TOTP code and enroll.
  const enrollCode = await computeTotp(totpSecret);
  console.log('[enrollTotpSecret] enrollment code:', enrollCode);

  // Find CSRF token in current nodes.
  let csrfForEnroll = '';
  for (const node of flowNodes) {
    if (
      node?.attributes?.name === 'csrf_token' &&
      node?.attributes?.type === 'hidden'
    ) {
      csrfForEnroll = node.attributes.value ?? '';
      break;
    }
  }

  const enrollResp = await ctx.request.post(flowAction, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    data: { csrf_token: csrfForEnroll, method: 'totp', totp_code: enrollCode },
    maxRedirects: 5,
  });

  const enrollStatus = enrollResp.status();
  console.log('[enrollTotpSecret] enrollment response status:', enrollStatus);
  if (enrollStatus >= 400 && enrollStatus !== 422) {
    const body = await enrollResp.text().catch(() => '');
    throw new Error(
      `enrollTotpSecret: TOTP enrollment failed: HTTP ${enrollStatus} — ${body.slice(0, 400)}`,
    );
  }

  return totpSecret;
}

/**
 * adminAal2Context — obtain a BrowserContext whose session is at AAL2.
 *
 * Sequence:
 *   1. Log in as admin (password → AAL1).
 *   2. enrollTotpSecret() — settings-flow TOTP enrollment (see above).
 *   3. Initiate an AAL2 login flow (?aal=aal2), compute a fresh code,
 *      submit it. The resulting session is at AAL2.
 *
 * The caller is responsible for closing the returned context after use.
 *
 * Throws if any step fails — a clear error message identifies which step.
 */
export async function adminAal2Context(opts: {
  browser: import('playwright-core').Browser;
  email: string;
  password: string;
  baseURL: string;
}): Promise<BrowserContext> {
  const { browser, email, password, baseURL } = opts;
  const ctx = await browser.newContext();

  try {
    // Step 1: AAL1 login.
    await loginViaJsonApi(ctx, { identifier: email, password }, baseURL);

    // Step 2: enroll TOTP (settings flow) and capture the secret.
    const totpSecret = await enrollTotpSecret(ctx, baseURL);

    // Step 3: AAL2 step-up login. Initiate a login flow with aal=aal2.
    const aal2FlowResp = await ctx.request.get(
      `${baseURL}/self-service/login/browser?aal=aal2&refresh=true`,
      { headers: { Accept: 'application/json' }, maxRedirects: 5 },
    );
    if (!aal2FlowResp.ok()) {
      throw new Error(
        `adminAal2Context: AAL2 login flow init failed: ${aal2FlowResp.status()}`,
      );
    }
    const aal2Flow = await aal2FlowResp.json() as {
      ui: {
        action: string;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        nodes: any[];
      };
    };

    // Compute a fresh code (step boundary may have advanced).
    const stepUpCode = await computeTotp(totpSecret);
    console.log('[adminAal2] step-up code:', stepUpCode);

    let csrfForStepUp = '';
    for (const node of aal2Flow.ui?.nodes ?? []) {
      if (
        node?.attributes?.name === 'csrf_token' &&
        node?.attributes?.type === 'hidden'
      ) {
        csrfForStepUp = node.attributes.value ?? '';
        break;
      }
    }

    const stepUpResp = await ctx.request.post(aal2Flow.ui?.action ?? '', {
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      data: { csrf_token: csrfForStepUp, method: 'totp', totp_code: stepUpCode },
      maxRedirects: 5,
    });

    const stepUpStatus = stepUpResp.status();
    console.log('[adminAal2] step-up response status:', stepUpStatus);
    if (!stepUpResp.ok() && stepUpStatus !== 422) {
      // 422 means the code window advanced; try one more time with a fresh code.
      const retryCode = await computeTotp(totpSecret);
      console.log('[adminAal2] retrying step-up with fresh code:', retryCode);
      const retryResp = await ctx.request.post(aal2Flow.ui?.action ?? '', {
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        data: { csrf_token: csrfForStepUp, method: 'totp', totp_code: retryCode },
        maxRedirects: 5,
      });
      if (!retryResp.ok()) {
        const body = await retryResp.text().catch(() => '');
        throw new Error(
          `adminAal2Context: AAL2 step-up failed after retry: HTTP ${retryResp.status()} — ${body.slice(0, 400)}`,
        );
      }
    }

    console.log('[adminAal2] AAL2 session established');
    return ctx;
  } catch (err) {
    await ctx.close();
    throw err;
  }
}

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

  // member: bt2@othala.test. Holds ONE group, `grafana-access`, which is the
  // entire basis for it reaching the grafana fixture — the converged access
  // model answers "can this person get in?" from that single group.
  //
  // Two separate non-admin properties, deliberately not conflated:
  //   - no metadata_admin.admin marker  → not a PORTAL admin (ADR 08), so
  //     /admin is closed to it (spec C).
  //   - no `grafana-admin` group        → `viewer` role inside Grafana, not
  //     admin (grafana.yaml group_role_map).
  // There are no cohort groups (family/friends/kids) anywhere in this suite;
  // they were retired with the converged model.
  member: [
    async ({ kratosAdminURL }, use) => {
      const result = await createIdentityWithPassword({
        email: 'bt2@othala.test',
        username: 'bt2',
        displayName: 'Browser Test 2',
        groups: ['grafana-access'],
        kratosAdminURL,
      });
      await use({ ...result, password: TEST_PASSWORD });
    },
    { scope: 'worker' },
  ],

  // admin: validate.sh pre-seeds this identity (ADMIN_EMAIL / ADMIN_USERNAME)
  // with metadata_admin.admin=true (ADR 08 marker) and groups
  // ['grafana-access','grafana-admin'] before Playwright starts. Both groups
  // are held EXPLICITLY: `grafana-access` is what admits it to the grafana
  // fixture (same group ordinary members hold) and `grafana-admin` is what
  // makes its role admin. Neither is derived from the other, and neither has
  // anything to do with the metadata_admin.admin marker below.
  // The fixture looks up the minted id by credentials_identifier. No OTHALA_ADMIN_IDS
  // env or portal recreate is involved — the portal reads the marker from the
  // Kratos admin API at request time.
  //
  // At AAL1 (password only), visiting /admin triggers an AAL2 step-up redirect.
  // Use adminAal2Context() for specs that need to reach /admin pages.
  admin: [
    async ({ kratosAdminURL }, use) => {
      const email = process.env.ADMIN_EMAIL ?? 'admin@othala.test';
      const password = process.env.ADMIN_PASSWORD ?? TEST_PASSWORD;
      // Look up the pre-seeded admin identity by credentials identifier.
      // validate.sh already created it with the admin marker; the 409-fallback
      // path in createIdentityWithPassword also does this lookup, so calling it
      // with the correct email would work — but issuing the lookup directly
      // avoids an unnecessary POST attempt.
      const listResp = await fetch(
        `${kratosAdminURL}/admin/identities?credentials_identifier=${encodeURIComponent(email)}`,
      );
      if (!listResp.ok) {
        throw new Error(
          `admin fixture: lookup failed: HTTP ${listResp.status} for ${email}`,
        );
      }
      const list = (await listResp.json()) as Array<{ id: string }>;
      if (list.length === 0) {
        throw new Error(
          `admin fixture: no identity found for ${email} — did validate.sh seed phase run?`,
        );
      }
      await use({ id: list[0].id, email, password });
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
