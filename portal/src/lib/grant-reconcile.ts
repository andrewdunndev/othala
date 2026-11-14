// Durable grant revocation. A credential change ends the person's app grants, but the Kratos hook that asks for it can be
// lost (a dropped request, a portal restart) and an admin-API change never fires it. So the portal records, in the
// identity's metadata_admin, the credential fingerprint its last revoke covered, and a timer sweep ends the grants of any
// identity whose credentials no longer match. The hook calls the same reconcile; the sweep is what makes it durable.

import { createHash } from 'node:crypto';
import type { Identity } from './types';

/** Credential types a person can change in settings: the five that carry a revoke-grants hook. */
const FINGERPRINTED = ['password', 'passkey', 'webauthn', 'totp', 'lookup_secret'] as const;

export interface GrantsMarker {
  /** The credential fingerprint the last revoke covered. */
  fp: string;
  /** ISO time the marker was written. */
  at: string;
}

const FP_RE = /^[0-9a-f]{64}$/;

/** The marker, or undefined when absent or malformed (a malformed one is treated as absent). */
export function readGrantsMarker(meta: unknown): GrantsMarker | undefined {
  if (!meta || typeof meta !== 'object') return undefined;
  const m = (meta as Record<string, unknown>).grants_revoked as Record<string, unknown> | null | undefined;
  if (!m || typeof m !== 'object') return undefined;
  return typeof m.fp === 'string' && FP_RE.test(m.fp) && typeof m.at === 'string' ? { fp: m.fp, at: m.at } : undefined;
}

const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const text = (v: unknown): string[] => (typeof v === 'string' && v !== '' ? [v] : []);

/**
 * What identifies the credential's current secret or key set, per type. Only fields a settings change or an admin write
 * alters: a sign-in writes none of them. Left out on purpose, because a sign-in rewrites them: a webauthn or passkey
 * authenticator's counters and flags, and a backup code's used_at. Also left out: timestamps and versions, display names,
 * and identifiers, which follow the person's email and username.
 */
function items(type: string, config: unknown): string[] {
  const c = (config && typeof config === 'object' ? config : {}) as Record<string, unknown>;
  switch (type) {
    case 'password':
      return text(c.hashed_password);
    case 'passkey':
    case 'webauthn':
      return asArray(c.credentials).flatMap((k) => text((k as Record<string, unknown> | null)?.id));
    case 'totp':
      return text(c.totp_url);
    case 'lookup_secret':
      return asArray(c.recovery_codes).flatMap((k) => text((k as Record<string, unknown> | null)?.code));
    default:
      return [];
  }
}

/**
 * SHA-256 over the canonical form of the identity's credential items. Secret-bearing items (the password hash, the TOTP
 * secret, backup codes) are only ever hashed; the result is not reversible and is never logged. A type with no items is
 * absent, so removing a credential changes the fingerprint exactly as adding one does.
 */
export function credentialFingerprint(identity: Pick<Identity, 'credentials'>): string {
  const creds = (identity.credentials ?? {}) as Record<string, { config?: unknown } | undefined>;
  const canonical = FINGERPRINTED.flatMap((type) => {
    const list = items(type, creds[type]?.config).sort();
    return list.length ? [[type, list]] : [];
  });
  return createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}

export interface ReconcileDeps {
  /** Ends the identity's Hydra login sessions and consent grants; throws on failure. */
  revokeGrants(id: string): Promise<void>;
  /** Writes the marker with one JSON Patch add on /metadata_admin/grants_revoked. */
  stampMarker(id: string, marker: GrantsMarker): Promise<void>;
  now?: () => Date;
}

export type ReconcileOutcome = 'stamped' | 'revoked' | 'current';

/**
 * One identity: no marker is stamped without revoking (an upgrade must not sign anyone out of their apps); a marker that
 * differs from the fingerprint revokes, then stamps. The stamp follows a successful revoke, so a failed revoke is retried
 * by the next pass.
 */
export async function reconcileIdentity(identity: Identity, deps: ReconcileDeps): Promise<ReconcileOutcome> {
  const fp = credentialFingerprint(identity);
  const held = readGrantsMarker(identity.metadata_admin);
  if (held?.fp === fp) return 'current';
  const outcome: ReconcileOutcome = held ? 'revoked' : 'stamped';
  if (held) await deps.revokeGrants(identity.id);
  await deps.stampMarker(identity.id, { fp, at: (deps.now?.() ?? new Date()).toISOString() });
  return outcome;
}

export interface SweepDeps extends ReconcileDeps {
  /** Every identity with credentials included, fully paginated. */
  listIdentities(): Promise<Identity[]>;
}

export interface SweepResult {
  stamped: number;
  revoked: number;
  failed: number;
}

/** Every identity once. One identity failing is logged by id and does not stop the rest. */
export async function sweepGrants(deps: SweepDeps, log: (msg: string) => void = console.error): Promise<SweepResult> {
  const result: SweepResult = { stamped: 0, revoked: 0, failed: 0 };
  for (const identity of await deps.listIdentities()) {
    try {
      const outcome = await reconcileIdentity(identity, deps);
      if (outcome === 'stamped') result.stamped++;
      if (outcome === 'revoked') result.revoked++;
    } catch (err) {
      result.failed++;
      log(`[portal/grant-sweep] identity_id=${JSON.stringify(identity.id)} not reconciled: ${(err as Error)?.message ?? err}`);
    }
  }
  return result;
}

export interface WebhookDeps extends ReconcileDeps {
  getIdentity(id: string): Promise<Identity>;
}

/**
 * The Kratos hook path: end the grants, then stamp the fingerprint read BEFORE the revoke, so a credential change that
 * lands mid-way is still seen by the next sweep. A revoke failure throws and leaves the marker alone; a failed read or
 * stamp is logged and leaves the grants revoked, which the sweep then re-covers.
 */
export async function revokeThenStamp(id: string, deps: WebhookDeps, log: (msg: string) => void = console.error): Promise<void> {
  let fp: string | undefined;
  try {
    fp = credentialFingerprint(await deps.getIdentity(id));
  } catch (err) {
    log(`[portal/revoke-grants] could not read credentials for identity_id=${JSON.stringify(id)}; marker not written: ${(err as Error)?.message ?? err}`);
  }
  await deps.revokeGrants(id);
  if (fp === undefined) return;
  try {
    await deps.stampMarker(id, { fp, at: (deps.now?.() ?? new Date()).toISOString() });
  } catch (err) {
    log(`[portal/revoke-grants] marker not written for identity_id=${JSON.stringify(id)}: ${(err as Error)?.message ?? err}`);
  }
}

export const SWEEP_INTERVAL_MS = 5 * 60 * 1000;

/** Runs `sweepGrants` now and then every `intervalMs`, never overlapping itself; returns a stop function. */
export function startGrantSweep(deps: SweepDeps, intervalMs: number = SWEEP_INTERVAL_MS, log: (msg: string) => void = console.error): () => void {
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const pass = async () => {
    try {
      const r = await sweepGrants(deps, log);
      if (r.revoked || r.stamped) console.log(`[portal/grant-sweep] revoked=${r.revoked} stamped=${r.stamped} failed=${r.failed}`);
    } catch (err) {
      log(`[portal/grant-sweep] sweep failed: ${(err as Error)?.message ?? err}`);
    }
    if (!stopped) {
      timer = setTimeout(pass, intervalMs);
      timer.unref();
    }
  };
  timer = setTimeout(pass, 0);
  timer.unref();
  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
  };
}
