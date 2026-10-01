// Dev-only settings-flow fixtures for `astro dev` (`/auth/settings?dev-state=<name>`): Kratos v26.2.0 settings flows
// as the browser flow API returns them, so the page iterates without a Kratos. Node names, groups, labels and label
// contexts follow ui/node/identifiers.go, x/webauthnx/nodes.go and text/message_settings.go in the Kratos source.
// settings.astro reads this only when import.meta.env.DEV is true; production never imports a state from here.

import type { FlowMessage, FlowNode, NodeInputAttributes, SettingsFlow } from './types';
import type { PasskeyNames } from './passkey-names';
import { RENAME_ERRORS } from './settings-flash';

export const DEV_SETTINGS_STATES = [
  'fresh',
  'enrolled',
  'totp-setup',
  'totp-wrong-code',
  'success',
  'reauth',
  'unverified',
  'rename-error',
  'codes-reveal',
  'codes-new',
  'replaced',
  'enrolled-admin',
] as const;
export type DevSettingsState = (typeof DEV_SETTINGS_STATES)[number];

export function isDevSettingsState(v: string | null): v is DevSettingsState {
  return v !== null && (DEV_SETTINGS_STATES as readonly string[]).includes(v);
}

export interface DevSettings {
  flow: SettingsFlow;
  emailVerified: boolean;
  names: PasskeyNames;
  /** True when the privileged window has lapsed, so the page offers to confirm the person's identity first. */
  reauth: boolean;
  /** The enrollment steps start open (a person who pressed Set up). */
  setupOpen: boolean;
  /** FLASH key of the saved line the fixture shows in its card, as the page script does after a live post. */
  flash: string | null;
  /** A refused passkey rename, as the page reads it from the one-shot cookie. */
  renameError: { id: string; text: string } | null;
  /** The identity carries the admin marker, so the second-factor gate refuses to drop its only second factor. */
  admin: boolean;
}

type Group = FlowNode['group'];

function input(group: Group, name: string, type: NodeInputAttributes['type'], extra: Partial<NodeInputAttributes> = {}, label?: string, messages?: FlowMessage[]): FlowNode {
  return {
    type: 'input',
    group,
    attributes: { name, type, node_type: 'input', required: false, disabled: false, ...extra },
    messages: messages ?? [],
    meta: label ? { label: { id: 0, text: label } } : {},
  };
}

const csrf = input('default', 'csrf_token', 'hidden', { value: 'dev-csrf-token', required: true });

const hex = (n: number) => n.toString(16).padStart(32, '0');

function removeNode(group: 'passkey' | 'webauthn', id: string, displayName: string, addedAt: string): FlowNode {
  const kind = group === 'passkey' ? 'passkey' : 'security key';
  const n = input(group, `${group}_remove`, 'submit', { value: id }, `Remove ${kind} "${displayName}"`);
  n.meta = {
    label: {
      id: group === 'passkey' ? 1050017 : 1050012,
      text: `Remove ${kind} "${displayName}"`,
      context: { display_name: displayName, added_at: addedAt, added_at_unix: Math.floor(Date.parse(addedAt) / 1000) },
    },
  };
  return n;
}

const PASSKEY_A = hex(0xa1);
const PASSKEY_B = hex(0xb2);
const KEY_A = hex(0xc3);
const PASSKEY_C = hex(0xd4);

function profileNodes(): FlowNode[] {
  return [
    input('profile', 'traits.email', 'email', { value: 'sam@example.test', required: true }, 'Email'),
    input('profile', 'traits.recoveryEmail', 'email', { value: '' }, 'Recovery email'),
    input('profile', 'traits.displayName', 'text', { value: 'Sam Rivera' }, 'Display name'),
    input('profile', 'traits.username', 'text', { value: 'sam', required: true }, 'Username'),
    input('profile', 'method', 'submit', { value: 'profile' }, 'Save'),
  ];
}

const passwordNodes = (): FlowNode[] => [
  input('password', 'password', 'password', { required: true, autocomplete: 'new-password' }, 'New password'),
  input('password', 'method', 'submit', { value: 'password' }, 'Save'),
];

function passkeyTail(): FlowNode[] {
  return [
    {
      ...input('passkey', 'passkey_register_trigger', 'button', { onclickTrigger: 'oryPasskeySettingsRegistration', onclick: 'window.oryPasskeySettingsRegistration()' }, 'Add passkey'),
    },
    input('passkey', 'passkey_settings_register', 'hidden', { value: '' }),
    input('passkey', 'passkey_create_data', 'hidden', { value: '{}' }),
  ];
}

function webauthnTail(): FlowNode[] {
  return [
    // Kratos serves this as an SRI script node; the dev route stands in so the swap can be walked against a loaded script.
    { type: 'script', group: 'webauthn', attributes: { node_type: 'script', id: 'webauthn_script', src: '/dev/webauthn.js', async: true, type: 'text/javascript' } as unknown as FlowNode['attributes'], messages: [], meta: {} },
    input('webauthn', 'webauthn_register_displayname', 'text', {}, 'Name of the security key'),
    input('webauthn', 'webauthn_register_trigger', 'button', { onclickTrigger: 'oryWebAuthnRegistration', onclick: 'window.oryWebAuthnRegistration({})' }, 'Add security key'),
    input('webauthn', 'webauthn_register', 'hidden', { value: '' }),
  ];
}

function totpEnrollNodes(wrongCode: boolean): FlowNode[] {
  const err: FlowMessage[] = wrongCode
    ? [{ id: 4000008, text: 'The provided authentication code is invalid, please try again.', type: 'error' }]
    : [];
  const svg =
    'data:image/svg+xml;utf8,' +
    encodeURIComponent(
      '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200" viewBox="0 0 200 200"><rect width="200" height="200" fill="#fff"/>' +
        '<path d="M16 16h48v48H16zM136 16h48v48h-48zM16 136h48v48H16z" fill="none" stroke="#000" stroke-width="8"/>' +
        '<path d="M28 28h24v24H28zM148 28h24v24h-24zM28 148h24v24H28zM88 20h16v16H88zM88 56h32v16H88zM72 88h16v32H72zM104 100h32v16h-32zM140 132h16v32h-16zM100 148h24v24h-24z" fill="#000"/></svg>',
    );
  return [
    { type: 'img', group: 'totp', attributes: { node_type: 'img', id: 'totp_qr', src: svg, width: 200, height: 200 }, messages: [], meta: { label: { id: 1050005, text: 'Authenticator app QR code' } } },
    { type: 'text', group: 'totp', attributes: { node_type: 'text', id: 'totp_secret_key', text: { id: 1050006, text: 'JBSWY3DPEHPK3PXP', type: 'info' } }, messages: [], meta: { label: { id: 1050007, text: 'This is your authenticator app secret. Use it if you can not scan the QR code.' } } },
    input('totp', 'totp_code', 'text', { required: true }, 'Verify code', err),
    input('totp', 'method', 'submit', { value: 'totp' }, 'Save'),
  ];
}

const totpEnrolledNodes = (): FlowNode[] => [
  input('totp', 'totp_unlink', 'submit', { value: 'true' }, 'Unlink TOTP Authenticator App'),
];

const CODES = ['k3m9-x2pq', 'b7wd-4nht', 'q8ze-j5cr', 'v2fa-m6ys', 'h4tk-p9ub', 'n5gx-c3ld', 'r6ja-w8eo', 'd9sv-y2mi', 's1pz-t7kh', 'e3uc-a4nf', 'x8lq-g6bw', 'z5ro-f1jd'];

/** The codes as Kratos serves them: one text node, joined with ", ", the per-code messages under context.secrets. */
function codesNode(): FlowNode {
  const secrets = CODES.map((c) => ({ id: 1050015, text: c, type: 'info', context: { secret: c } }));
  return {
    type: 'text',
    group: 'lookup_secret',
    attributes: { node_type: 'text', id: 'lookup_secret_codes', text: { id: 1050014, text: CODES.join(', '), type: 'info', context: { secrets } } },
    messages: [],
    meta: { label: { id: 1050013, text: 'These are your back up recovery codes. Please keep them in a safe place!' } },
  } as FlowNode;
}

function lookupNodes(mode: boolean | 'reveal' | 'new'): FlowNode[] {
  if (mode === 'reveal') {
    return [
      codesNode(),
      input('lookup_secret', 'lookup_secret_regenerate', 'submit', { value: 'true' }, 'Generate new backup recovery codes'),
      input('lookup_secret', 'lookup_secret_disable', 'submit', { value: 'true' }, 'Disable this method'),
    ];
  }
  if (mode === 'new') {
    return [codesNode(), input('lookup_secret', 'lookup_secret_confirm', 'submit', { value: 'true' }, 'Confirm backup recovery codes')];
  }
  return mode
    ? [
        input('lookup_secret', 'lookup_secret_reveal', 'submit', { value: 'true' }, 'Reveal backup recovery codes'),
        input('lookup_secret', 'lookup_secret_disable', 'submit', { value: 'true' }, 'Disable this method'),
      ]
    : [input('lookup_secret', 'lookup_secret_regenerate', 'submit', { value: 'true' }, 'Generate new backup recovery codes')];
}

interface Spec {
  passkeys: Array<[string, string, string]>;
  keys: Array<[string, string, string]>;
  totp: 'none' | 'qr' | 'wrong' | 'enrolled';
  lookup: boolean | 'reveal' | 'new';
  next: DevSettingsState;
}

function build(spec: Spec, state: DevSettingsState, extra: { success?: boolean; verified?: boolean; reauth?: boolean; names?: PasskeyNames; setupOpen?: boolean; admin?: boolean; flash?: string; renameError?: DevSettings['renameError'] } = {}): DevSettings {
  const nodes: FlowNode[] = [
    csrf,
    ...profileNodes(),
    ...spec.passkeys.map(([id, name, at]) => removeNode('passkey', id, name, at)),
    ...passkeyTail(),
    ...passwordNodes(),
    ...(spec.totp === 'enrolled' ? totpEnrolledNodes() : totpEnrollNodes(spec.totp === 'wrong')),
    ...lookupNodes(spec.lookup),
    ...spec.keys.map(([id, name, at]) => removeNode('webauthn', id, name, at)),
    ...webauthnTail(),
  ];
  const messages: FlowMessage[] = extra.success ? [{ id: 1050001, text: 'Your changes have been saved!', type: 'success' }] : [];
  const flow: SettingsFlow = {
    id: `dev-flow-${state}`,
    type: 'browser',
    expires_at: '2099-01-01T00:00:00Z',
    issued_at: '2026-09-30T12:00:00Z',
    request_url: 'http://127.0.0.1/self-service/settings/browser',
    // A post lands on the next state, so the enhancement and native fallback can both be walked in dev.
    ui: { action: `/auth/settings?dev-state=${spec.next}`, method: 'POST', nodes, messages },
    identity: undefined as unknown as SettingsFlow['identity'],
    state: extra.success ? 'success' : 'show_form',
  };
  return {
    flow,
    emailVerified: extra.verified !== false,
    names: extra.names ?? {},
    reauth: extra.reauth === true,
    setupOpen: extra.setupOpen === true,
    flash: extra.flash ?? null,
    renameError: extra.renameError ?? null,
    admin: extra.admin === true,
  };
}

const PK_A: [string, string, string] = [PASSKEY_A, 'unnamed', '2026-06-12T09:30:00Z'];
const PK_B: [string, string, string] = [PASSKEY_B, 'unnamed', '2026-08-03T18:05:00Z'];
// A platform authenticator names itself (its AAGUID's name) when the person has not chosen one.
const PK_C: [string, string, string] = [PASSKEY_C, 'iCloud Keychain', '2026-09-02T14:20:00Z'];
const KEY: [string, string, string] = [KEY_A, 'Keyring key', '2026-07-21T07:10:00Z'];

export function devSettings(state: DevSettingsState): DevSettings {
  switch (state) {
    case 'fresh':
      return build({ passkeys: [], keys: [], totp: 'qr', lookup: false, next: 'fresh' }, state);
    case 'enrolled':
      return build({ passkeys: [PK_A, PK_B, PK_C], keys: [KEY], totp: 'enrolled', lookup: true, next: 'enrolled' }, state, {
        names: { [PASSKEY_B]: 'Pixel phone' },
      });
    case 'totp-setup':
      return build({ passkeys: [PK_A], keys: [], totp: 'qr', lookup: false, next: 'totp-wrong-code' }, state, { setupOpen: true });
    case 'totp-wrong-code':
      return build({ passkeys: [PK_A], keys: [], totp: 'wrong', lookup: false, next: 'success' }, state);
    case 'success':
      return build({ passkeys: [PK_A], keys: [], totp: 'enrolled', lookup: false, next: 'success' }, state, { success: true, flash: 'method:totp' });
    case 'reauth':
      return build({ passkeys: [PK_A, PK_B], keys: [], totp: 'qr', lookup: true, next: 'reauth' }, state, { reauth: true });
    case 'rename-error':
      return build({ passkeys: [PK_A, PK_B], keys: [], totp: 'enrolled', lookup: true, next: 'rename-error' }, state, {
        renameError: { id: PASSKEY_B, text: RENAME_ERRORS.name },
      });
    case 'codes-reveal':
      return build({ passkeys: [PK_A, PK_B], keys: [], totp: 'enrolled', lookup: 'reveal', next: 'codes-reveal' }, state);
    case 'codes-new':
      return build({ passkeys: [PK_A, PK_B], keys: [], totp: 'enrolled', lookup: 'new', next: 'enrolled' }, state, { flash: 'lookup_secret_regenerate' });
    case 'replaced':
      return build({ passkeys: [PK_A], keys: [], totp: 'qr', lookup: false, next: 'totp-wrong-code' }, state, { setupOpen: true, flash: 'totp_replace' });
    case 'enrolled-admin':
      return build({ passkeys: [PK_A, PK_B], keys: [], totp: 'enrolled', lookup: true, next: 'enrolled-admin' }, state, { admin: true });
    case 'unverified':
      return build({ passkeys: [PK_A, PK_B], keys: [], totp: 'enrolled', lookup: true, next: 'unverified' }, state, { verified: false });
  }
}
