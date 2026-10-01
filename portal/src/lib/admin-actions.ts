// The admin POST actions from pages/admin/users/[id].astro, so the page is a
// thin dispatch. CSRF verification stays page-level, before any handler runs.
// Each handler takes the FormData plus an ActionContext (the identity already
// loaded) and returns an ActionOutcome; `refetch` asks the page to reload().

import {
  listIdentities,
  updateIdentity,
  deleteIdentity,
  deactivateIdentity,
  reactivateIdentity,
  getRecoveryLink,
  patchAdminMarker,
  patchPrerequisites,
  markEmailVerified,
  deleteCredential,
  EVICTABLE_CREDENTIAL_TYPES,
} from './admin-api';
import { revokeUserSessions, type RevokeUserResult } from './admin';
import { isAdminMarker } from './admin-auth';
import { hasSecondFactor } from './step-up';
import { sendInviteRecoveryEmail } from './kratos';
import { confirmsInviteAddress, IDENTITY_GROUP_ORDER, normalizeGroupOrder, shouldRefuseRecovery } from './access';
import { accessToStorage, choicesFromForm } from './access-rows';
import { GROUP_RE } from './access-groups';
import { HOUSEHOLD_GROUPS } from './constants';
import { identityGroups as storedGroups, planGroupSave } from './gate';
import { buildGroupRegistry, isIdentityGroup, unconfiguredGroups } from './group-registry';
import { revokeConsentSessions, revokeSubject } from './revoke';
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
  | { kind: 'email-verified' }
  | { kind: 'prerequisites-saved' }
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
  /** Names defined under requirements/, the only prerequisites an admin can mark. */
  requirements?: readonly string[];
}

type ActionHandler = (fd: FormData, ctx: ActionContext) => Promise<ActionOutcome | Response>;

// HIGH-3 / D1 gate: refuse admin-to-admin recovery via the UI (issue-recovery
// and send-invite-email share this — see shouldRefuseRecovery, access.ts).
const ADMIN_RECOVERY_REFUSAL: ActionResult = {
  kind: 'error',
  message: 'A setup link for an admin cannot be made here. Use the server console.',
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
  if (rawRecoveryEmail && !EMAIL_RE.test(rawRecoveryEmail)) formErrors.recoveryEmail = 'Enter a valid recovery email address.';
  if (!USERNAME_RE.test(traits.username)) formErrors.username = 'Use a username like first.last (letters and numbers, with a dot).';
  if (!EMAIL_RE.test(traits.email)) formErrors.email = 'Enter a valid email address.';
  const identityGroups = fd.getAll('identityGroups').map(String).filter(Boolean);
  const accessGroups = fd.getAll('accessGroups').map(String).filter(Boolean);
  if (identityGroups.length === 0) formErrors.identityGroups = 'Pick at least one household group.';

  // Stored groups the form renders no checkbox for stay unless removed by an
  // explicit tick. They never count toward the identity-group minimum above.
  const clearUnconfigured = new Set(fd.getAll('clearUnconfigured').map(String));
  const keptUnconfigured = unconfiguredGroups(
    buildGroupRegistry(manifests, IDENTITY_GROUP_ORDER),
    storedGroups(identity),
  ).filter((g) => !clearUnconfigured.has(g));

  // Repair surface for refuseNonCanonical (gate.ts): planGroupSave decides
  // the write from the STORED identity, never from submitted checkboxes.
  const groupPlan = planGroupSave(
    identity,
    [...identityGroups, ...accessGroups, ...keptUnconfigured],
    fd.getAll('clearNonCanonical').map(String),
  );
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

  // Preserve the existing admin marker and prerequisite marks: an unrelated groups/roles edit must
  // not silently drop them. Read from the pre-dispatch identity, not re-fetched
  // (avoids a TOCTOU on the write; grant/revoke are the targeted paths).
  const existingAdmin = identity.metadata_admin?.admin;
  const existingPrerequisites = identity.metadata_admin?.prerequisites;
  const existingPasskeyNames = identity.metadata_admin?.passkeyNames;
  const groups = normalizeGroupOrder(groupPlan.groups);
  await updateIdentity(id, {
    traits,
    metadataAdmin: {
      groups,
      roles: Object.keys(roles).length ? roles : undefined,
      ...(existingAdmin === true ? { admin: true } : {}),
      ...(existingPrerequisites?.length ? { prerequisites: existingPrerequisites } : {}),
      ...(existingPasskeyNames && Object.keys(existingPasskeyNames).length ? { passkeyNames: existingPasskeyNames } : {}),
    },
  });
  // The Kratos write has landed; now end grants issued under the old access.
  // A failure here cannot roll the save back, so it is reported as an error
  // that says the save stood.
  if (narrowsAccess(identity, groups, roles)) {
    const failure = await revokeGrants(id);
    if (failure) return { actionResult: failure, mode: 'read', refetch: true };
  }
  return { actionResult: { kind: 'updated', removed: groupPlan.removed }, mode: 'read', refetch: true };
}

interface SectionEdit {
  /** Replaces the identity's traits; absent keeps the stored ones. */
  profile?: { username: string; email: string; displayName: string; recoveryEmail: string };
  /** Replaces the household groups the page offers; absent keeps the stored ones. */
  household?: readonly string[];
  /** Replaces the app groups and role overrides; absent keeps the stored ones. */
  access?: { groups: readonly string[]; roles: Readonly<Record<string, string>> };
  /** Stored groups to remove outright. */
  remove?: readonly string[];
}

/**
 * The person page saves one section at a time. Each section builds the full form saveAction already guards (traits,
 * groups, roles) from what is stored plus its own edit, so every section keeps the same narrowing revocation and
 * repair rules and no section can clobber another's data.
 */
function sectionSave(ctx: ActionContext, edit: SectionEdit): Promise<ActionOutcome> {
  const { identity, manifests } = ctx;
  const registry = buildGroupRegistry(manifests, IDENTITY_GROUP_ORDER);
  const stored = storedGroups(identity);
  const storedUnconfigured = unconfiguredGroups(registry, stored);
  const desired = edit.access ? [...edit.access.groups] : [...stored];
  const roles = edit.access ? edit.access.roles : (identity.metadata_admin?.roles ?? {});
  const traits = identity.traits;

  const fd = new FormData();
  fd.set('username', edit.profile?.username ?? String(traits?.username ?? ''));
  fd.set('email', edit.profile?.email ?? String(traits?.email ?? ''));
  fd.set('displayName', edit.profile?.displayName ?? String(traits?.displayName ?? ''));
  fd.set('recoveryEmail', edit.profile?.recoveryEmail ?? String(traits?.recoveryEmail ?? ''));

  // Identity groups the page does not offer (the legacy `admin` group) ride along unchanged.
  const unoffered = stored.filter((g) => isIdentityGroup(registry, g) && !HOUSEHOLD_GROUPS.includes(g));
  const household = edit.household
    ? [...edit.household.filter((g) => HOUSEHOLD_GROUPS.includes(g)), ...unoffered]
    : desired.filter((g) => isIdentityGroup(registry, g));
  for (const g of household) fd.append('identityGroups', g);

  const removing = new Set(edit.remove ?? []);
  for (const g of desired) {
    if (isIdentityGroup(registry, g) || storedUnconfigured.includes(g) || removing.has(g)) continue;
    fd.append('accessGroups', g);
  }
  // A stored group the access edit dropped goes through the explicit clear path saveAction guards.
  for (const g of storedUnconfigured) {
    if (removing.has(g) || (edit.access && !desired.includes(g))) fd.append('clearUnconfigured', g);
  }
  for (const g of removing) if (!GROUP_RE.test(g)) fd.append('clearNonCanonical', g);
  for (const [clientId, role] of Object.entries(roles)) fd.set(`role:${clientId}`, role);
  return saveAction(fd, ctx);
}

const TRAIT_FIELDS = ['username', 'email', 'displayName', 'recoveryEmail'] as const;

/** Save the apps section: the submitted app -> level choices become groups and role overrides. */
export function saveAccessAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const roles = { ...(ctx.identity.metadata_admin?.roles ?? {}) };
  const access = accessToStorage(ctx.manifests, choicesFromForm(fd), { groups: storedGroups(ctx.identity), roles });
  return sectionSave(ctx, { access });
}

/** Save the household section: the ticked household groups. */
export function saveHouseholdAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  return sectionSave(ctx, { household: fd.getAll('identityGroups').map(String) });
}

/** Save the profile: name, username, email and recovery email. */
export function saveProfileAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const [username, email, displayName, recoveryEmail] = TRAIT_FIELDS.map((k) => String(fd.get(k) ?? '').trim());
  return sectionSave(ctx, { profile: { username: username.toLowerCase(), email, displayName, recoveryEmail } });
}

/** Remove unrecognised stored groups, each named by the admin who sees the raw string in the warning card. */
export function removeGroupsAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  return sectionSave(ctx, { remove: fd.getAll('group').map(String).filter(Boolean) });
}

/** Admin vouches for the email trait's address; the only write is that one address. */
export async function markVerifiedAction(_fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  if (!ctx.identity.traits?.email) {
    return { actionResult: { kind: 'error', message: 'This person has no email address on file.' }, refetch: false };
  }
  await markEmailVerified(ctx.id);
  return { actionResult: { kind: 'email-verified' }, refetch: true };
}

/** The prerequisites to store: marks for names that are no longer defined stay, defined names follow the submitted ticks. */
export function nextPrerequisites(stored: readonly string[], known: readonly string[], submitted: readonly string[]): string[] {
  return [...stored.filter((n) => !known.includes(n)), ...known.filter((n) => submitted.includes(n))];
}

/** Save which prerequisites the admin has marked set up for this person, a targeted patch that touches nothing else. */
export async function setPrerequisitesAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const next = nextPrerequisites(
    ctx.identity.metadata_admin?.prerequisites ?? [],
    ctx.requirements ?? [],
    fd.getAll('prerequisite').map(String),
  );
  await patchPrerequisites(ctx.id, next);
  return { actionResult: { kind: 'prerequisites-saved' }, refetch: true };
}

/** True when the save drops a stored group or changes or drops a stored role. */
export function narrowsAccess(identity: Identity, groups: readonly string[], roles: Record<string, string>): boolean {
  const stored = identity.metadata_admin;
  if ((stored?.groups ?? []).some((g) => !groups.includes(g))) return true;
  return Object.entries(stored?.roles ?? {}).some(([clientId, role]) => roles[clientId] !== role);
}

async function revokeGrants(id: string): Promise<ActionResult | null> {
  try {
    await revokeConsentSessions(id);
    return null;
  } catch (err) {
    return {
      kind: 'error',
      message: `Saved, but existing app grants could not be revoked: ${err instanceof Error ? err.message : 'unknown error'}`,
    };
  }
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
  if (!targetEmail) return { actionResult: { kind: 'error', message: 'This person has no email address on file.' }, refetch: false };

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

function isActiveAdmin(identity: Identity): boolean {
  return isAdminMarker(identity) && identity.state !== 'inactive';
}

/** True when taking `target` out of service would leave no active admin. */
async function leavesNoActiveAdmin(target: Identity): Promise<boolean> {
  if (!isActiveAdmin(target)) return false;
  const active = (await listIdentities()).filter(isActiveAdmin).length;
  return active <= 1;
}

export async function deactivateAction(_fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const username = ctx.identity.traits?.username ?? ctx.id;
  if (ctx.id === ctx.adminIdentityId) {
    return {
      actionResult: {
        kind: 'error',
        message: 'You cannot turn off your own sign-in. Ask another admin to do it.',
      },
      refetch: false,
    };
  }
  if (await leavesNoActiveAdmin(ctx.identity)) {
    return {
      actionResult: { kind: 'error', message: `Refusing to deactivate: ${username} is the last active admin. Make someone else an admin first.` },
      refetch: false,
    };
  }
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
  // Deactivate and cut sessions and Hydra grants first: Hydra keeps consent
  // and refresh tokens by subject, and nothing reaches them once the identity
  // is gone. A failed delete then leaves an inactive identity the gate denies.
  try {
    await revokeSubject(id, { deactivate: true });
  } catch (err) {
    return {
      actionResult: {
        kind: 'error',
        message: `Not deleted: sessions and app grants could not be revoked first. ${err instanceof Error ? err.message : 'unknown error'}`,
      },
      refetch: false,
    };
  }
  try {
    await deleteIdentity(id);
  } catch (err) {
    return {
      actionResult: {
        kind: 'error',
        message: `Revoked and deactivated, but not deleted: ${err instanceof Error ? err.message : 'unknown error'}`,
      },
      refetch: true,
    };
  }
  return new Response(null, { status: 303, headers: { Location: '/admin/users?deleted=1' } });
}

// Admin accounts always step up at app sign-in, so the marker requires a totp
// or webauthn credential to step up with, and keeps requiring one.
const SECOND_FACTOR_REQUIRED: ActionResult = {
  kind: 'error',
  message: 'Admin accounts need an authenticator app or security key enrolled.',
};

const OWN_SECOND_FACTOR_REQUIRED: ActionResult = {
  kind: 'error',
  message: 'You cannot remove your own last authenticator app or security key. Enroll another one first.',
};

export async function grantAdminAction(_fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const username = ctx.identity.traits?.username ?? ctx.id;
  if (!hasSecondFactor(ctx.identity)) {
    return { actionResult: SECOND_FACTOR_REQUIRED, refetch: false };
  }
  await patchAdminMarker(ctx.id, true);
  return { actionResult: { kind: 'admin-granted', username }, refetch: true };
}

export async function revokeAdminAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome | Response> {
  const { id, identity, adminIdentityId } = ctx;
  const username = identity.traits?.username ?? id;
  const self = id === adminIdentityId;
  // Giving up your own admin access is allowed, but only by typing your own name or username, so it cannot happen by a stray click.
  const typed = String(fd.get('confirm') ?? '').trim();
  const displayName = String(identity.traits?.displayName ?? '').trim();
  if (self && typed !== username && (displayName === '' || typed !== displayName)) {
    return {
      actionResult: { kind: 'error', message: `Type your name (${displayName || username}) to give up your own admin access.` },
      refetch: false,
    };
  }
  // Last-admin guard: refuse if this would leave zero active admins.
  if (await leavesNoActiveAdmin(identity)) {
    return {
      actionResult: { kind: 'error', message: `Refusing to revoke: ${username} is the last active admin. Make someone else an admin first.` },
      refetch: false,
    };
  }
  await patchAdminMarker(id, false);
  const failure = await revokeGrants(id);
  if (self) return new Response(null, { status: 303, headers: { Location: '/' } });
  if (failure) return { actionResult: failure, refetch: true };
  return { actionResult: { kind: 'admin-revoked', username }, refetch: true };
}

// Kratos upstream cannot admin-delete a passkey credential (identity/handler.go
// deleteIdentityCredentials, v26.2.0 — no passkey case, unconditional 400; see
// issue #10 and admin-api.ts EVICTABLE_CREDENTIAL_TYPES). Refuse it here too,
// server-side, in case a stale form ever submits cred_type=passkey — the
// message matches the note rendered next to the passkey chip.
const PASSKEY_REFUSAL: ActionResult = {
  kind: 'error',
  message: 'A passkey cannot be removed by an admin. Sign them out everywhere, then they can remove it in their own settings.',
};

export async function removeCredentialAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const credType = String(fd.get('cred_type') ?? '').trim();
  if (credType === 'passkey') {
    return { actionResult: PASSKEY_REFUSAL, refetch: false };
  }
  if (!EVICTABLE_CREDENTIAL_TYPES.has(credType)) {
    return {
      actionResult: { kind: 'error', message: `That kind of sign-in method cannot be removed here.` },
      refetch: false,
    };
  }
  const self = ctx.id === ctx.adminIdentityId;
  if (self || isAdminMarker(ctx.identity)) {
    const creds = { ...(ctx.identity.credentials ?? {}) } as Record<string, unknown>;
    delete creds[credType];
    if (!hasSecondFactor({ ...ctx.identity, credentials: creds as Identity['credentials'] })) {
      return { actionResult: self ? OWN_SECOND_FACTOR_REQUIRED : SECOND_FACTOR_REQUIRED, refetch: false };
    }
  }
  await deleteCredential(ctx.id, credType);
  return { actionResult: { kind: 'credential-removed', credType }, refetch: true };
}

/** Dispatch table keyed by the form's `action` field — the page's whole switch. */
export const ADMIN_ACTIONS: Record<string, ActionHandler> = {
  'save-access': saveAccessAction,
  'save-household': saveHouseholdAction,
  'save-profile': saveProfileAction,
  'remove-groups': removeGroupsAction,
  'mark-verified': markVerifiedAction,
  'set-prerequisites': setPrerequisitesAction,
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
