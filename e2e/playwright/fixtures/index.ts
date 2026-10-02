/**
 * Othala fixtures: edge and Ory URLs, seeded member/admin (worker-scoped), a closing ctx,
 * a virtual passkey authenticator, and adminAal2Context (TOTP cannot be seeded; it is
 * enrolled through the settings flow at runtime).
 */

import { test as base } from '@playwright/test';
import type { BrowserContext, CDPSession } from 'playwright-core';
import { createIdentityWithPassword, TEST_PASSWORD, type SeedResult } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';

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

export async function computeTotp(secret: string, t?: number): Promise<string> {
  const { createHmac } = await import('node:crypto');
  const keyBytes = base32Decode(secret);
  const counter = BigInt(Math.floor((t ?? Date.now() / 1000) / 30));
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(counter);
  const hmac = createHmac('sha1', Buffer.from(keyBytes));
  hmac.update(counterBuf);
  const digest = hmac.digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const code =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(code % 1_000_000).padStart(6, '0');
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractTotpSecret(flowNodes: any[]): string {
  for (const node of flowNodes ?? []) {
    if (node?.group !== 'totp') continue;
    const attrs = node?.attributes;
    if (
      attrs &&
      (attrs.node_type === 'text' || node?.type === 'text') &&
      typeof attrs?.text?.text === 'string' &&
      (attrs.text?.id === 1050015 || /^[A-Z2-7]{16,}$/i.test(attrs.text.text))
    ) {
      return attrs.text.text;
    }
  }
  return '';
}

export async function enrollTotpSecret(
  ctx: BrowserContext,
  baseURL: string,
): Promise<string> {
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

  let totpSecret = extractTotpSecret(settingsFlow.ui?.nodes ?? []);
  let flowAction: string = settingsFlow.ui?.action ?? '';
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let flowNodes: any[] = settingsFlow.ui?.nodes ?? [];

  if (!totpSecret) {
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

  const enrollCode = await computeTotp(totpSecret);
  console.log('[enrollTotpSecret] enrollment code:', enrollCode);

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

export async function adminAal2Context(opts: {
  browser: import('playwright-core').Browser;
  email: string;
  password: string;
  baseURL: string;
}): Promise<BrowserContext> {
  const { browser, email, password, baseURL } = opts;
  const ctx = await browser.newContext();

  try {
    await loginViaJsonApi(ctx, { identifier: email, password }, baseURL);

    const totpSecret = await enrollTotpSecret(ctx, baseURL);

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

interface VirtualAuthenticatorOptions {
  protocol: 'u2f' | 'ctap2';
  transport: 'usb' | 'nfc' | 'ble' | 'cable' | 'internal';
  hasResidentKey: boolean;
  hasUserVerification: boolean;
  isUserVerified: boolean;
  automaticPresenceSimulation?: boolean;
}

export const GRAFANA_CLIENT_ID = 'grafana';
export const GRAFANA_REDIRECT_URI = 'https://grafana.othala.test/login/generic_oauth';
export const KRATOS_ADMIN_URL = 'http://kratos:4434';

export interface OthalaWorkerFixtures {
  kratosAdminURL: string;
  hydraPublicURL: string;
  hydraAdminURL: string;
  member: SeedResult & { password: string };
  admin: SeedResult & { password: string };
}

export interface OthalaFixtures {
  baseURL: string;
  /** Fresh isolated browser context, closed after the test. */
  ctx: BrowserContext;
  /** Override any subset of the virtual authenticator options (test-scoped). */
  virtualAuthenticatorOptions: Partial<VirtualAuthenticatorOptions>;
  /** CDP session attached to the current page (test-scoped). */
  pageCDPSession: CDPSession;
  /** CDP virtual authenticator id (test-scoped). Cleaned up after each test. */
  virtualAuthenticator: { authenticatorId: string };
}

export const test = base.extend<OthalaFixtures, OthalaWorkerFixtures>({
  baseURL: async ({}, use) => {
    await use(process.env.BASE ?? 'http://auth.othala.test');
  },

  kratosAdminURL: [async ({}, use) => {
    await use(KRATOS_ADMIN_URL);
  }, { scope: 'worker' }],

  hydraPublicURL: [async ({}, use) => {
    await use('http://hydra:4444');
  }, { scope: 'worker' }],

  hydraAdminURL: [async ({}, use) => {
    await use('http://hydra:4445');
  }, { scope: 'worker' }],

  ctx: async ({ browser }, use) => {
    const ctx = await browser.newContext();
    await use(ctx);
    await ctx.close();
  },

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

  admin: [
    async ({ kratosAdminURL }, use) => {
      const email = process.env.ADMIN_EMAIL ?? 'admin@othala.test';
      const password = process.env.ADMIN_PASSWORD ?? TEST_PASSWORD;
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

  virtualAuthenticatorOptions: async ({}, use) => {
    await use({});
  },

  pageCDPSession: async ({ page }, use) => {
    const cdpSession = await page.context().newCDPSession(page);
    await use(cdpSession);
    await cdpSession.detach();
  },

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
