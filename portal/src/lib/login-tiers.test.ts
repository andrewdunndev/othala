// Invariant: deriveLoginTiers never counts non-credential nodes as a second factor.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { deriveLoginTiers } from './login-tiers.js';
import type { LoginFlow } from './types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadFixture(name: string): LoginFlow {
  const raw = readFileSync(join(__dirname, 'fixtures', name), 'utf-8');
  return JSON.parse(raw) as unknown as LoginFlow;
}

describe('deriveLoginTiers — captured production AAL1 flow (webauthn glue script present)', () => {
  const flow = loadFixture('login-aal1-captured.json');

  it('is NOT treated as an aal2 step-up', () => {
    const tiers = deriveLoginTiers(flow);
    expect(tiers.isAal2).toBe(false);
    expect(tiers.hasAal2Methods).toBe(false);
  });

  it('derives all three primary tiers present', () => {
    const tiers = deriveLoginTiers(flow);
    expect(tiers.hasPasskey).toBe(true);
    expect(tiers.hasCode).toBe(true);
    expect(tiers.hasPassword).toBe(true);
  });

  it('counts zero second-factor nodes — the webauthn script node is not an input', () => {
    const tiers = deriveLoginTiers(flow);
    expect(tiers.totpNodes).toHaveLength(0);
    expect(tiers.aal2WebauthnNodes).toHaveLength(0);
    expect(tiers.lookupNodes).toHaveLength(0);
  });
});

function aal2Flow(): LoginFlow {
  return {
    id: 'aal2-flow-id',
    type: 'browser',
    expires_at: '2026-08-22T15:00:00Z',
    issued_at: '2026-08-22T14:50:00Z',
    request_url: 'https://dag.dunn.dev/self-service/login/browser?aal=aal2',
    requested_aal: 'aal2',
    ui: {
      action: 'https://dag.dunn.dev/self-service/login?flow=aal2-flow-id',
      method: 'POST',
      nodes: [
        {
          type: 'input',
          group: 'default',
          attributes: {
            name: 'csrf_token',
            type: 'hidden',
            value: 'csrf-value',
            required: true,
            disabled: false,
            node_type: 'input',
          },
          messages: [],
          meta: {},
        },
        {
          type: 'input',
          group: 'totp',
          attributes: {
            name: 'totp_code',
            type: 'text',
            required: true,
            disabled: false,
            node_type: 'input',
          },
          messages: [],
          meta: { label: { text: 'Authenticator code' } },
        },
        {
          type: 'input',
          group: 'totp',
          attributes: {
            name: 'method',
            type: 'submit',
            value: 'totp',
            disabled: false,
            node_type: 'input',
          },
          messages: [],
          meta: { label: { text: 'Verify code' } },
        },
      ],
    },
  } as unknown as LoginFlow;
}

describe('deriveLoginTiers — genuine AAL2 step-up flow', () => {
  it('IS treated as an aal2 step-up, with the totp input node counted', () => {
    const tiers = deriveLoginTiers(aal2Flow());
    expect(tiers.isAal2).toBe(true);
    expect(tiers.hasAal2Methods).toBe(true);
    expect(tiers.totpNodes.length).toBeGreaterThan(0);
  });
});

function freshAal1FlowNoWebauthn(): LoginFlow {
  return {
    id: 'fresh-aal1-flow-id',
    type: 'browser',
    expires_at: '2026-08-22T15:00:00Z',
    issued_at: '2026-08-22T14:50:00Z',
    request_url: 'https://dag.dunn.dev/self-service/login/browser',
    requested_aal: 'aal1',
    ui: {
      action: 'https://dag.dunn.dev/self-service/login?flow=fresh-aal1-flow-id',
      method: 'POST',
      nodes: [
        {
          type: 'input',
          group: 'default',
          attributes: {
            name: 'csrf_token',
            type: 'hidden',
            value: 'csrf-value',
            required: true,
            disabled: false,
            node_type: 'input',
          },
          messages: [],
          meta: {},
        },
        {
          type: 'input',
          group: 'default',
          attributes: {
            name: 'identifier',
            type: 'text',
            value: '',
            required: true,
            disabled: false,
            node_type: 'input',
          },
          messages: [],
          meta: { label: { text: 'ID' } },
        },
        {
          type: 'input',
          group: 'code',
          attributes: {
            name: 'method',
            type: 'submit',
            value: 'code',
            disabled: false,
            node_type: 'input',
          },
          messages: [],
          meta: { label: { text: 'Send sign in code' } },
        },
        {
          type: 'input',
          group: 'password',
          attributes: {
            name: 'password',
            type: 'password',
            required: true,
            autocomplete: 'current-password',
            disabled: false,
            node_type: 'input',
          },
          messages: [],
          meta: { label: { text: 'Password' } },
        },
        {
          type: 'input',
          group: 'password',
          attributes: {
            name: 'method',
            type: 'submit',
            value: 'password',
            disabled: false,
            node_type: 'input',
          },
          messages: [],
          meta: { label: { text: 'Sign in with password' } },
        },
      ],
    },
  } as unknown as LoginFlow;
}

describe('deriveLoginTiers — fresh AAL1 flow with no webauthn method at all', () => {
  it('is NOT a step-up, and tiers read off whichever nodes are present', () => {
    const tiers = deriveLoginTiers(freshAal1FlowNoWebauthn());
    expect(tiers.isAal2).toBe(false);
    expect(tiers.hasAal2Methods).toBe(false);
    expect(tiers.hasPasskey).toBe(false); // no passkey group node in this fixture
    expect(tiers.hasCode).toBe(true);
    expect(tiers.hasPassword).toBe(true);
    expect(tiers.totpNodes).toHaveLength(0);
    expect(tiers.aal2WebauthnNodes).toHaveLength(0);
    expect(tiers.lookupNodes).toHaveLength(0);
  });
});
