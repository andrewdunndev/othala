#!/usr/bin/env node
/* eslint-disable no-console */
//
// Build-time prepass: read every `hydra/clients/*.yaml` from the auth repo
// and emit a single JSON bundle the Workers SSR side imports at build time.
//
// Workers can't read the filesystem at runtime, so the manifest catalog has
// to be baked into the bundle. Vite/Astro inline `src/data/manifests.json`
// when it's referenced via a normal `import` statement, so this script just
// needs to keep that file in sync with the yaml on disk.
//
// Output shape per client:
//   {
//     clientId: "keep",
//     clientName: "Vaultwarden",
//     redirectUris: [...],
//     scopes: ["openid", "email", "profile", "groups", "offline_access"],
//     audience: [...],
//     accessGroup: "access-keep",
//     roles: [{ name: "user", description: "..." }, ...],   // may be empty
//     groupRoleMap: { admin: "admin", family: "user", ... } // may be empty
//   }
//
// `accessGroup` is conventionally `access-<clientId>`; the home portal tile
// launcher and the Effective Access view both use that mapping.

import { readFileSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));
const portalRoot = resolve(here, '..');
const repoRoot = resolve(portalRoot, '..');
const clientsDir = join(repoRoot, 'hydra', 'clients');
const outFile = join(portalRoot, 'src', 'data', 'manifests.json');

function splitScope(scope) {
  if (!scope) return [];
  if (Array.isArray(scope)) return scope;
  return String(scope).split(/\s+/).filter(Boolean);
}

function normaliseRoles(raw) {
  if (!raw) return [];
  // Accept both array form and map form for ergonomics in the yaml.
  if (Array.isArray(raw)) {
    return raw
      .filter((r) => r && typeof r === 'object' && r.name)
      .map((r) => ({ name: String(r.name), description: String(r.description ?? '') }));
  }
  if (typeof raw === 'object') {
    return Object.entries(raw).map(([name, v]) => ({
      name,
      description: String((v && v.description) ?? ''),
    }));
  }
  return [];
}

function normaliseGroupRoleMap(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

function loadClient(file) {
  const path = join(clientsDir, file);
  const yaml = parseYaml(readFileSync(path, 'utf8')) ?? {};

  // Namespace split (D6 / C3): yamls now have `oidc:` and `consent:`
  // top-level blocks. The pre-namespace flat shape is rejected by the
  // consent service loader; this script refuses it too so a stale
  // checkout doesn't silently bake legacy data into the bundle.
  const oidc = yaml.oidc;
  const consent = yaml.consent;
  const looksLikeLegacy =
    yaml.client_id !== undefined ||
    yaml.client_name !== undefined ||
    yaml.grant_types !== undefined ||
    yaml.roles !== undefined ||
    yaml.group_role_map !== undefined;
  if (!oidc && looksLikeLegacy) {
    throw new Error(
      `${file}: pre-namespace flat shape detected. Migrate to oidc:/consent: blocks; see hydra/clients/keep.yaml.`,
    );
  }
  if (!oidc || typeof oidc !== 'object') {
    throw new Error(`${file}: missing or non-object oidc: block`);
  }

  const clientId = String(oidc.client_id ?? file.replace(/\.ya?ml$/, ''));
  const consentBlock = consent && typeof consent === 'object' ? consent : {};
  return {
    clientId,
    clientName: String(oidc.client_name ?? clientId),
    redirectUris: Array.isArray(oidc.redirect_uris) ? oidc.redirect_uris.map(String) : [],
    postLogoutRedirectUris: Array.isArray(oidc.post_logout_redirect_uris)
      ? oidc.post_logout_redirect_uris.map(String)
      : [],
    scopes: splitScope(oidc.scope),
    audience: Array.isArray(oidc.audience) ? oidc.audience.map(String) : [],
    grantTypes: Array.isArray(oidc.grant_types) ? oidc.grant_types.map(String) : [],
    skipConsent: Boolean(oidc.skip_consent ?? false),
    backchannelLogoutUri: oidc.backchannel_logout_uri ? String(oidc.backchannel_logout_uri) : '',
    accessGroup: `access-${clientId}`,
    roles: normaliseRoles(consentBlock.roles),
    groupRoleMap: normaliseGroupRoleMap(consentBlock.group_role_map),
  };
}

function main() {
  const files = readdirSync(clientsDir)
    .filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
    .sort();
  const manifests = files.map(loadClient);
  mkdirSync(dirname(outFile), { recursive: true });
  writeFileSync(outFile, JSON.stringify(manifests, null, 2) + '\n');
  console.log(`manifests-build: wrote ${manifests.length} clients to ${outFile}`);
}

main();
