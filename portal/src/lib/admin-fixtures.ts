// Dev-only admin fixtures for `astro dev` (`/admin/users?dev-state=<name>`): a small household over the e2e fixture apps,
// so the admin pages iterate without Kratos or a manifest directory. The admin pages read this only when
// import.meta.env.DEV is true; production never imports a state from here.

import type { ClientManifest } from './manifests';
import type { Identity } from './types';
import { DEV_AVATAR } from './dev-avatar';
import { joinApps, type AdminApp } from './admin-view';
import type { AppTile } from './tiles';
import type { ActionResult } from './admin-actions';

export const DEV_ADMIN_STATES = ['household', 'many', 'empty', 'broken'] as const;
export type DevAdminState = (typeof DEV_ADMIN_STATES)[number];

export function isDevAdminState(v: string | null): v is DevAdminState {
  return v !== null && (DEV_ADMIN_STATES as readonly string[]).includes(v);
}

const role = (name: string, description: string) => ({ name, description, claimEmit: {} });

function manifest(slug: string, name: string, over: Partial<ClientManifest>): ClientManifest {
  return {
    clientId: slug,
    presentationOnly: false,
    clientName: name,
    redirectUris: [`https://${slug}.example.test/callback`],
    postLogoutRedirectUris: [],
    scopes: ['openid', 'email', 'profile', 'groups'],
    scope: 'openid email profile groups',
    audience: [`https://${slug}.example.test`],
    grantTypes: ['authorization_code', 'refresh_token'],
    responseTypes: ['code'],
    tokenEndpointAuthMethod: 'client_secret_basic',
    skipConsent: true,
    backchannelLogoutUri: '',
    backchannelLogoutSessionRequired: false,
    accessGroups: [`${slug}-access`],
    roles: [],
    groupRoleMap: {},
    emitGroupsClaim: true,
    skipAccessCheck: false,
    sourcePath: `${slug}.yaml`,
    ...over,
  };
}

const MANIFESTS: ClientManifest[] = [
  manifest('grafana', 'Grafana', {
    roles: [
      role('admin', 'Instance and org admin.'),
      role('editor', 'Create and edit dashboards.'),
      role('viewer', 'Read-only dashboard access.'),
    ],
    groupRoleMap: { 'grafana-admin': 'admin' },
  }),
  manifest('audiobookshelf', 'Audiobookshelf', {
    roles: [role('admin', 'Server admin: users, libraries, settings.'), role('user', 'Listen and sync progress.')],
    groupRoleMap: { 'audiobookshelf-access': 'user' },
  }),
  manifest('promptdesk', 'Prompt', {
    roles: [role('admin', 'Model management and workspace settings.'), role('user', 'Chat access across permitted models.')],
    groupRoleMap: { 'prompt-access': 'user' },
    accessGroups: ['prompt-access'],
  }),
  manifest('proxywatch', 'Proxywatch', { presentationOnly: true, accessGroups: ['proxywatch-access'] }),
  manifest('statuspage', 'Statuspage', { presentationOnly: true, accessGroups: [], skipAccessCheck: true }),
];

const DESCRIPTIONS: Record<string, [string, string, string, string]> = {
  grafana: ['Dashboards and metrics at a glance.', 'https://grafana.example.test', 'GR', 'oidc'],
  audiobookshelf: ['Audiobook and podcast server with progress sync.', 'https://audiobookshelf.example.test', 'AB', 'oidc'],
  promptdesk: ['Internal chat interface.', 'https://promptdesk.example.test', 'PR', 'oidc'],
  proxywatch: ['Internal monitoring tool gated at the edge.', 'https://proxywatch.example.test', 'PW', 'forward_auth'],
  statuspage: ['Public status and incident history.', 'https://statuspage.example.test', 'SP', 'external'],
};

function tile(m: ClientManifest, order: number): AppTile {
  const [description, url, icon, authKind] = DESCRIPTIONS[m.clientId];
  return {
    slug: m.clientId,
    name: m.clientName,
    description,
    url,
    icon,
    authKind,
    accessGroups: m.accessGroups,
    order,
    disabled: false,
    fqdn: new URL(url).hostname,
    requires: m.clientId === 'proxywatch' ? ['tailscale'] : [],
  } as AppTile;
}

const STAMP = new Date('2026-01-01T00:00:00Z');
const key = (n: number, passwordless: boolean) => ({ id: `key-${n}`, public_key: 'cHVibGlj', attestation_type: 'none', is_passwordless: passwordless });
const CONFIG: Record<string, object> = {
  password: { hashed_password: 'x' },
  totp: { totp_url: 'otpauth://totp/othala:dev?secret=JBSWY3DPEHPK3PXP' },
  webauthn: { credentials: [key(1, false)] },
  passkey: { credentials: [key(2, true)] },
  lookup_secret: { recovery_codes: [{ code: 'aaaa-bbbb' }] },
};
const cred = (type: string, identifiers: string[]) => ({ type, identifiers, config: CONFIG[type] ?? {}, version: 0, created_at: STAMP, updated_at: STAMP });

interface Seed {
  id: string;
  username: string;
  displayName: string;
  groups: string[];
  roles?: Record<string, string>;
  admin?: boolean;
  unverified?: boolean;
  off?: boolean;
  creds?: string[];
  prerequisites?: string[];
  avatar?: boolean;
}

function person(s: Seed): Identity {
  const email = `${s.username.replace('.', '')}@example.test`;
  return {
    id: s.id,
    schema_id: 'family',
    schema_url: '',
    state: s.off ? 'inactive' : 'active',
    traits: { username: s.username, email, displayName: s.displayName },
    verifiable_addresses: [
      { value: email, via: 'email', verified: !s.unverified, status: s.unverified ? 'pending' : 'completed', created_at: STAMP, updated_at: STAMP },
    ],
    credentials: Object.fromEntries((s.creds ?? ['password']).map((t) => [t, cred(t, [s.username])])),
    metadata_admin: {
      groups: s.groups,
      ...(s.roles ? { roles: s.roles } : {}),
      ...(s.admin ? { admin: true } : {}),
      ...(s.prerequisites ? { prerequisites: s.prerequisites } : {}),
      ...(s.avatar ? { avatar: DEV_AVATAR } : {}),
    },
  } as unknown as Identity;
}

const HOUSEHOLD: Seed[] = [
  { id: 'dev-amy', username: 'amy.park', displayName: 'Amy Park', admin: true, creds: ['password', 'totp', 'webauthn', 'lookup_secret'], groups: ['everyone', 'grafana-access', 'grafana-admin', 'audiobookshelf-access', 'prompt-access', 'proxywatch-access'], roles: { audiobookshelf: 'admin' }, prerequisites: ['tailscale'] },
  { id: 'dev-ben', username: 'ben.okafor', displayName: 'Ben Okafor', admin: true, avatar: true, creds: ['password', 'totp'], groups: ['everyone', 'grafana-access', 'prompt-access'], roles: { grafana: 'editor' } },
  { id: 'dev-cleo', username: 'cleo.marsh', displayName: 'Cleo Marsh', unverified: true, creds: ['password', 'passkey'], groups: ['everyone', 'audiobookshelf-access', 'proxywatch-access'] },
  { id: 'dev-dev', username: 'dev.rao', displayName: 'Dev Rao', off: true, groups: ['everyone', 'grafana-access'] },
  { id: 'dev-eli', username: 'eli.stone', displayName: 'Eli Stone', creds: ['password', 'passkey', 'totp'], groups: ['everyone', 'prompt-access', 'garden', 'Old Name'] },
  { id: 'dev-fay', username: 'fay.lindqvist', displayName: 'Fay Lindqvist', creds: [], groups: ['everyone'] },
];

const MORE: Seed[] = ['gus.hale', 'hana.ito', 'ivan.petrov', 'jo.mbeki'].map((username, n) => ({
  id: `dev-more-${n}`,
  username,
  displayName: username.split('.').map((p) => p[0].toUpperCase() + p.slice(1)).join(' '),
  groups: n % 2 === 0 ? ['everyone', 'grafana-access'] : ['everyone'],
}));

export interface DevAdmin {
  /** The signed-in admin, who is also the first person in the list. */
  adminId: string;
  identities: Identity[];
  apps: AdminApp[];
  /** Requirement names the person page offers as prerequisites. */
  requirements: { name: string; title: string; why: string }[];
  /** True when the app catalog failed to load, so the pages show the stale-catalog notice. */
  broken: boolean;
  /** Client ids the sign-in service does not have yet (dev has no service to ask). */
  unsynced: string[];
}

export function devAdmin(state: DevAdminState): DevAdmin {
  // The broken state also carries one app whose group name fails lint, so its row shows a problem badge.
  const manifests = state === 'broken' ? MANIFESTS.map((m) => (m.clientId === 'promptdesk' ? { ...m, accessGroups: ['Prompt Access'] } : m)) : MANIFESTS;
  const seeds = state === 'empty' ? HOUSEHOLD.slice(0, 1) : state === 'many' ? [...HOUSEHOLD, ...MORE] : HOUSEHOLD;
  return {
    adminId: 'dev-amy',
    identities: seeds.map(person),
    apps: joinApps(manifests, manifests.map((m, n) => tile(m, n))),
    requirements: [
      { name: 'tailscale', title: 'Tailscale', why: 'Some apps are reachable only on the private network.' },
      { name: 'vpn', title: 'VPN profile', why: 'Needed away from home.' },
    ],
    broken: state === 'broken',
    unsynced: state === 'broken' ? ['audiobookshelf'] : [],
  };
}

/**
 * What a person-page POST shows in `astro dev`: the success result of each action, so the banners and the setup-link
 * card can be seen. Nothing is written; the fixture household stays as it was.
 */
const NOTHING_SAVED: ActionResult = { kind: 'error', message: 'Preview data: nothing was saved, so this page keeps showing the old state.' };

/** Previews hand-over actions with a believable result; any action that would change what the page shows says nothing was saved. */
export function devActionResult(action: string): ActionResult {
  switch (action) {
    case 'issue-recovery':
      return { kind: 'recovery', url: 'https://auth.example.test/self-service/recovery?flow=fixture&token=fixture', code: '123456', expiresAt: '' };
    case 'force-relogin':
      return { kind: 'revoked', result: {} as never };
    default:
      return NOTHING_SAVED;
  }
}
