// The 10 admin POST actions from pages/admin/users/[id].astro, extracted so
// the page's frontmatter is a thin dispatch. CSRF verification is
// action-name-keyed and stays page-level, BEFORE any handler here runs.
//
// Every handler takes the raw FormData plus an ActionContext (the identity
// already loaded pre-dispatch — never re-fetched here) and returns an
// ActionOutcome for the page to apply to its render locals. `refetch` tells
// the page to re-run its own reload() after a mutation; none of the values
// in ActionResult depend on the reloaded identity, so deferring the reload
// to the page changes nothing observable.

import {
  listIdentities,
  updateIdentity,
  deleteIdentity,
  deactivateIdentity,
  reactivateIdentity,
  getRecoveryLink,
  patchAdminMarker,
  revokeUserSessions,
  type RevokeUserResult,
} from './admin';
import { deleteCredential, EVICTABLE_CREDENTIAL_TYPES } from './admin-api';
import { isAdminMarker } from './admin-auth';
import { sendInviteRecoveryEmail } from './kratos';
import { confirmsInviteAddress, normalizeGroupOrder, shouldRefuseRecovery } from './access';
import { planGroupSave } from './gate';
import type { ClientManifest } from './manifests';
import type { Identity } from './types';

const USERNAME_RE = /^[a-z0-9]+(?:\.[a-z0-9]+)+$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** TTL passed to getRecoveryLink — quoted by the page's enrollment-pair copy too. */
export const ENROLLMENT_TTL = '24h';

export type ActionResult =
  | { kind: 'recovery'; url: string; code: string; expiresAt: string }
  | { kind: 'invite-email'; email: string }
  | { kind: 'deactivated'; username: string }
  | { kind: 'reactivated'; username: string }
  | { kind: 'updated'; removed: string[] }
  | { kind: 'admin-granted'; username: string }
  | { kind: 'admin-revoked'; username: string }
  | { kind: 'revoked'; result: RevokeUserResult }
  | { kind: 'credential-removed'; credType: string }
  | { kind: 'error'; message: string };

export interface ActionOutcome {
  /** Absent only on save's validation-failure path (re-render with formErrors, no notice). */
  actionResult?: ActionResult;
  /** True when the page must re-run its own reload() after this mutation. */
  refetch: boolean;
  /** save only. */
  formErrors?: Record<string, string>;
  /** save only, on success. */
  mode?: 'read';
}

export interface ActionContext {
  id: string;
  identity: Identity;
  adminIdentityId: string;
  manifests: ClientManifest[];
}

type ActionHandler = (fd: FormData, ctx: ActionContext) => Promise<ActionOutcome | Response>;

// HIGH-3 / D1 gate: refuse admin-to-admin recovery via the UI (issue-recovery
// and send-invite-email share this — see shouldRefuseRecovery, access.ts).
const ADMIN_RECOVERY_REFUSAL: ActionResult = {
  kind: 'error',
  message: 'Admin recovery is console-only. See docs/runbooks/admin-recovery.md.',
};

export async function saveAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const { id, identity, manifests } = ctx;
  const rawRecoveryEmail = String(fd.get('recoveryEmail') ?? '').trim();
  const traits = {
    username: String(fd.get('username') ?? '').trim().toLowerCase(),
    email: String(fd.get('email') ?? '').trim(),
    displayName: String(fd.get('displayName') ?? '').trim() || undefined,
    recoveryEmail: rawRecoveryEmail && EMAIL_RE.test(rawRecoveryEmail) ? rawRecoveryEmail : undefined,
  };
  const formErrors: Record<string, string> = {};
  if (rawRecoveryEmail && !EMAIL_RE.test(rawRecoveryEmail)) formErrors.recoveryEmail = 'Invalid recovery email address.';
  if (!USERNAME_RE.test(traits.username)) formErrors.username = 'Invalid username pattern.';
  if (!EMAIL_RE.test(traits.email)) formErrors.email = 'Invalid email.';
  const identityGroups = fd.getAll('identityGroups').map(String).filter(Boolean);
  const accessGroups = fd.getAll('accessGroups').map(String).filter(Boolean);
  if (identityGroups.length === 0) formErrors.identityGroups = 'Pick at least one identity group.';

  // Repair surface for refuseNonCanonical (gate.ts): planGroupSave decides
  // the write from the STORED identity, never from submitted checkboxes.
  const groupPlan = planGroupSave(identity, [...identityGroups, ...accessGroups], fd.getAll('clearNonCanonical').map(String));
  if (groupPlan.refusal) formErrors.nonCanonicalGroups = groupPlan.refusal;

  const knownClientIds = new Set(manifests.map((m) => m.clientId));
  const roles: Record<string, string> = {};
  for (const m of manifests) {
    const v = String(fd.get(`role:${m.clientId}`) ?? '').trim();
    if (v) roles[m.clientId] = v;
  }
  for (const clientId of Object.keys(roles)) {
    if (!knownClientIds.has(clientId)) delete roles[clientId];
  }

  if (Object.keys(formErrors).length > 0) {
    return { formErrors, refetch: false };
  }

  // Preserve the existing admin marker: an unrelated groups/roles edit must
  // not silently drop it. Read from the pre-dispatch identity, not re-fetched
  // (avoids a TOCTOU on the write; grant/revoke are the targeted paths).
  const existingAdmin = identity.metadata_admin?.admin;
  await updateIdentity(id, {
    traits,
    metadataAdmin: {
      groups: normalizeGroupOrder(groupPlan.groups),
      roles: Object.keys(roles).length ? roles : undefined,
      ...(existingAdmin === true ? { admin: true } : {}),
    },
  });
  return { actionResult: { kind: 'updated', removed: groupPlan.removed }, mode: 'read', refetch: true };
}

export async function issueRecoveryAction(_fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  if (shouldRefuseRecovery(ctx.identity)) return { actionResult: ADMIN_RECOVERY_REFUSAL, refetch: false };
  const link = await getRecoveryLink(ctx.id, ENROLLMENT_TTL);
  return {
    actionResult: { kind: 'recovery', url: link.recovery_link, code: link.recovery_code, expiresAt: link.expires_at },
    refetch: false,
  };
}

export async function sendInviteEmailAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  if (shouldRefuseRecovery(ctx.identity)) return { actionResult: ADMIN_RECOVERY_REFUSAL, refetch: false };
  const targetEmail = ctx.identity.traits?.email;
  if (!targetEmail) return { actionResult: { kind: 'error', message: 'Identity has no email trait on file.' }, refetch: false };

  // Send-time address confirmation, SERVER-enforced (D1 addendum,
  // DECISIONS.md): a UI-only check is not an invariant.
  const confirmEmail = String(fd.get('confirmEmail') ?? '');
  if (!confirmsInviteAddress(confirmEmail, targetEmail)) {
    return {
      actionResult: { kind: 'error', message: 'Confirmation address does not match the address on file. Nothing was sent.' },
      refetch: false,
    };
  }
  try {
    await sendInviteRecoveryEmail(targetEmail);
    return { actionResult: { kind: 'invite-email', email: targetEmail }, refetch: false };
  } catch (err) {
    // Never interpolate the address into the surfaced message.
    return {
      actionResult: { kind: 'error', message: `Invite email failed: ${err instanceof Error ? err.message : 'unknown error'}` },
      refetch: false,
    };
  }
}

export async function forceReloginAction(_fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const result = await revokeUserSessions(ctx.id);
  return { actionResult: { kind: 'revoked', result }, refetch: false };
}

export async function deactivateAction(_fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const username = ctx.identity.traits?.username ?? ctx.id;
  await deactivateIdentity(ctx.id);
  return { actionResult: { kind: 'deactivated', username }, refetch: true };
}

export async function reactivateAction(_fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const username = ctx.identity.traits?.username ?? ctx.id;
  await reactivateIdentity(ctx.id);
  return { actionResult: { kind: 'reactivated', username }, refetch: true };
}

export async function deleteAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome | Response> {
  const { id, identity } = ctx;
  // Closes the delete-the-last-admin lockout (and covers self-delete, since
  // self is admin): an admin-marked target must be revoke-admin'd first,
  // which enforces the last-admin guard. Checked before the confirm text so
  // an admin target is refused regardless of what was typed.
  if (isAdminMarker(identity)) {
    return {
      actionResult: {
        kind: 'error',
        message: 'Cannot delete an admin identity. Revoke admin authority first — that path enforces the last-admin guard.',
      },
      refetch: false,
    };
  }
  const expected = identity.traits?.username ?? '';
  const confirm = String(fd.get('confirm') ?? '').trim();
  if (confirm !== expected) {
    return { actionResult: { kind: 'error', message: `Type the username (${expected}) to confirm deletion.` }, refetch: false };
  }
  await deleteIdentity(id);
  return new Response(null, { status: 303, headers: { Location: '/admin/users?deleted=1' } });
}

export async function grantAdminAction(_fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const username = ctx.identity.traits?.username ?? ctx.id;
  await patchAdminMarker(ctx.id, true);
  return { actionResult: { kind: 'admin-granted', username }, refetch: true };
}

export async function revokeAdminAction(_fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const { id, identity, adminIdentityId } = ctx;
  const username = identity.traits?.username ?? id;
  // Self-demote guard: break-glass scenario requires another admin or console access.
  if (id === adminIdentityId) {
    return {
      actionResult: {
        kind: 'error',
        message:
          'You cannot revoke your own admin marker via the UI. Have another admin do it, or use the shell break-glass (see docs/runbooks/admin-recovery.md).',
      },
      refetch: false,
    };
  }
  // Last-admin guard: refuse if this would leave zero admins.
  const all = await listIdentities();
  const adminCount = all.filter((i) => (i.metadata_admin as Record<string, unknown> | undefined)?.['admin'] === true).length;
  if (adminCount <= 1) {
    return {
      actionResult: { kind: 'error', message: `Refusing to revoke: ${username} is the last admin. Grant admin to another identity first.` },
      refetch: false,
    };
  }
  await patchAdminMarker(id, false);
  return { actionResult: { kind: 'admin-revoked', username }, refetch: true };
}

// Kratos upstream cannot admin-delete a passkey credential (identity/handler.go
// deleteIdentityCredentials, v26.2.0 — no passkey case, unconditional 400; see
// issue #10 and admin-api.ts EVICTABLE_CREDENTIAL_TYPES). Refuse it here too,
// server-side, in case a stale form ever submits cred_type=passkey — the
// message matches the note rendered next to the passkey chip.
const PASSKEY_REFUSAL: ActionResult = {
  kind: 'error',
  message: 'Passkeys cannot be admin-deleted (Kratos upstream limitation). Revoke sessions, then have the user self-remove the credential at /auth/settings — or delete the identity as a last resort.',
};

export async function removeCredentialAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const credType = String(fd.get('cred_type') ?? '').trim();
  if (credType === 'passkey') {
    return { actionResult: PASSKEY_REFUSAL, refetch: false };
  }
  if (!EVICTABLE_CREDENTIAL_TYPES.has(credType)) {
    return {
      actionResult: { kind: 'error', message: `Invalid credential type '${credType}'. Evictable types: webauthn, totp, lookup_secret.` },
      refetch: false,
    };
  }
  await deleteCredential(ctx.id, credType);
  return { actionResult: { kind: 'credential-removed', credType }, refetch: true };
}

/** Dispatch table keyed by the form's `action` field — the page's whole switch. */
export const ADMIN_ACTIONS: Record<string, ActionHandler> = {
  save: saveAction,
  'issue-recovery': issueRecoveryAction,
  'send-invite-email': sendInviteEmailAction,
  'force-relogin': forceReloginAction,
  deactivate: deactivateAction,
  reactivate: reactivateAction,
  delete: deleteAction,
  'grant-admin': grantAdminAction,
  'revoke-admin': revokeAdminAction,
  'remove-credential': removeCredentialAction,
};
