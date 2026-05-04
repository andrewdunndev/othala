// OIDC client manifest loader for SSR pages.
//
// The catalog is a JSON dump baked into the Worker bundle at build time
// (Workers can't read the filesystem at runtime). The dump is regenerated
// from `hydra/clients/*.yaml` by `scripts/manifests-build.mjs`, which the
// `prebuild` and `manifests:build` npm scripts wire up.
//
// Source of truth is the yaml on disk; this is just the cached
// admin-UI-friendly view.

import manifestsJson from '../data/manifests.json';

export interface ClientRole {
  name: string;
  description: string;
}

export interface ClientManifest {
  clientId: string;
  clientName: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  scopes: string[];
  audience: string[];
  grantTypes: string[];
  skipConsent: boolean;
  /**
   * OIDC Back-Channel Logout 1.0 endpoint, when the app supports it.
   * Empty string when the yaml leaves the field absent (Tailscale, vLLM,
   * BookLore, current Jellyfin SSO plugin). The admin "Force re-login"
   * action posts a signed logout token to this URI per supported app.
   */
  backchannelLogoutUri: string;
  /** Conventional `access-<clientId>` group that grants entry to this app. */
  accessGroup: string;
  /** Declared role enum for the app; may be empty if the yaml has no `roles:` block. */
  roles: ClientRole[];
  /** identity-group → role-name map; what role a member of <group> gets by default. */
  groupRoleMap: Record<string, string>;
}

const manifests = manifestsJson as ClientManifest[];

/** Return all known clients sorted by clientId. */
export function loadClientManifests(): ClientManifest[] {
  return manifests;
}

export function getClientManifest(clientId: string): ClientManifest | undefined {
  return manifests.find((m) => m.clientId === clientId);
}

/** Distinct identity groups referenced by any client's group_role_map. */
export function knownIdentityGroups(): string[] {
  const set = new Set<string>(['admin', 'family', 'friends', 'kids']);
  for (const m of manifests) {
    for (const g of Object.keys(m.groupRoleMap)) set.add(g);
  }
  return Array.from(set).sort();
}

/** Distinct access groups across all clients. */
export function knownAccessGroups(): string[] {
  return manifests.map((m) => m.accessGroup).sort();
}
