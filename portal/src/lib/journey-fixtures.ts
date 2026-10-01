// Dev-only fixtures for the first-run pages under `astro dev` (`?dev-state=<name>` on /auth/login, /auth/recovery,
// /auth/verification and /auth/consent): Kratos browser flows as the API returns them, and a consent request, so each
// page iterates without a Kratos or a Hydra. The pages read this only when import.meta.env.DEV is true.

import type { FlowMessage, FlowNode, LoginFlow, NodeInputAttributes, RecoveryFlow, VerificationFlow } from './types';

type Group = FlowNode['group'];

function node(group: Group, name: string, type: NodeInputAttributes['type'], extra: Partial<NodeInputAttributes> = {}, label?: string, messages: FlowMessage[] = []): FlowNode {
  return {
    type: 'input',
    group,
    attributes: { name, type, node_type: 'input', required: false, disabled: false, ...extra },
    messages,
    meta: label ? { label: { id: 0, text: label } } : {},
  };
}

const csrf = node('default', 'csrf_token', 'hidden', { value: 'dev-csrf-token', required: true });
const error = (text: string, id = 4060006): FlowMessage => ({ id, text, type: 'error' });

function base(path: string, nodes: FlowNode[], messages: FlowMessage[] = []) {
  return {
    id: 'dev-flow',
    type: 'browser' as const,
    expires_at: '2099-01-01T00:00:00Z',
    issued_at: '2026-01-01T00:00:00Z',
    request_url: `http://localhost${path}`,
    ui: { action: '#', method: 'POST' as const, nodes, messages },
  };
}

export const DEV_RECOVERY_STATES = ['request', 'code', 'code-prefilled', 'code-wrong'] as const;
export const DEV_VERIFICATION_STATES = ['request', 'code'] as const;
export const DEV_LOGIN_STATES = ['code', 'aal2', 'wrong-password'] as const;
export const DEV_CONSENT_STATES = ['consent', 'consent-unknown-app', 'consent-error'] as const;

export const isIn = <T extends readonly string[]>(list: T, v: string | null): v is T[number] =>
  v !== null && (list as readonly string[]).includes(v);

export function devRecovery(state: (typeof DEV_RECOVERY_STATES)[number]): RecoveryFlow {
  if (state === 'request') {
    return {
      ...base('/auth/recovery', [csrf, node('code', 'email', 'email', { required: true }, 'Email'), node('code', 'method', 'submit', { value: 'code' }, 'Submit')]),
      state: 'choose_method',
      active: 'code',
    };
  }
  const wrong = state === 'code-wrong';
  return {
    ...base(
      '/auth/recovery',
      [
        csrf,
        node('code', 'code', 'text', { required: true, ...(state === 'code-prefilled' ? { value: '482913' } : wrong ? { value: '000000' } : {}) }, 'Recovery code',
          wrong ? [error('The recovery code is invalid or has already been used. Please try again.')] : []),
        node('code', 'method', 'submit', { value: 'code' }, 'Continue'),
        node('code', 'email', 'submit', { value: 'dev@example.test' }, 'Resend code'),
      ],
      [{ id: 1060003, text: 'An email containing a recovery code has been sent to the email address you provided.', type: 'info' }],
    ),
    state: 'sent_email',
    active: 'code',
  };
}

export function devVerification(state: (typeof DEV_VERIFICATION_STATES)[number]): VerificationFlow {
  if (state === 'request') {
    return {
      ...base('/auth/verification', [csrf, node('code', 'email', 'email', { required: true }, 'Email'), node('code', 'method', 'submit', { value: 'code' }, 'Submit')]),
      state: 'choose_method',
      active: 'code',
    };
  }
  return {
    ...base('/auth/verification', [
      csrf,
      node('code', 'code', 'text', { required: true }, 'Verification code'),
      node('code', 'method', 'submit', { value: 'code' }, 'Continue'),
      node('code', 'email', 'submit', { value: 'dev@example.test' }, 'Resend code'),
    ]),
    state: 'sent_email',
    active: 'code',
  };
}

const passkeyNodes = [
  node('passkey', 'passkey_login', 'hidden', { value: '' }),
  node('passkey', 'passkey_login_trigger', 'button', { onclickTrigger: 'oryPasskeyLogin' }, 'Sign in with passkey'),
];

export function devLogin(state: (typeof DEV_LOGIN_STATES)[number]): LoginFlow {
  if (state === 'aal2') {
    return {
      ...base('/auth/login?aal=aal2', [
        csrf,
        node('totp', 'totp_code', 'text', { required: true }, 'Authentication code'),
        node('totp', 'method', 'submit', { value: 'totp' }, 'Continue'),
        node('lookup_secret', 'lookup_secret', 'text', { required: true }, 'Backup recovery code'),
        node('lookup_secret', 'method', 'submit', { value: 'lookup_secret' }, 'Continue'),
      ]),
      requested_aal: 'aal2',
    };
  }
  const primary = [
    csrf,
    node('default', 'identifier', 'hidden', { value: 'dev@example.test' }),
    ...passkeyNodes,
    node('password', 'identifier', 'text', { required: true }, 'ID'),
    node('password', 'password', 'password', { required: true }, 'Password'),
    node('password', 'method', 'submit', { value: 'password' }, 'Sign in'),
  ];
  if (state === 'code') {
    return {
      ...base('/auth/login', [
        ...primary,
        node('code', 'code', 'text', { required: true }, 'Login code'),
        node('code', 'method', 'submit', { value: 'code' }, 'Continue'),
        node('code', 'resend', 'submit', { value: 'code' }, 'Resend code'),
      ]),
      requested_aal: 'aal1',
    };
  }
  return {
    ...base('/auth/login', [...primary, node('code', 'method', 'submit', { value: 'code' }, 'Send sign-in code')], [
      error('The provided credentials are invalid, check for spelling mistakes in your password or username, email address, or phone number.', 4000006),
    ]),
    requested_aal: 'aal1',
  };
}

export interface DevConsent {
  clientId: string;
  clientName: string;
  scopes: string[];
  /** The consent request or session could not be read, as the live page reports. */
  fetchError?: boolean;
}

export function devConsent(state: (typeof DEV_CONSENT_STATES)[number]): DevConsent {
  const scopes = ['openid', 'profile', 'email', 'groups'];
  if (state === 'consent-unknown-app') return { clientId: 'new-app', clientName: 'New app', scopes };
  if (state === 'consent-error') return { clientId: 'dev-app', clientName: 'Dev app', scopes, fetchError: true };
  return { clientId: 'dev-app', clientName: 'Dev app', scopes };
}
