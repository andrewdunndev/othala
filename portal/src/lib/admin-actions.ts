// The page verifies CSRF before any handler runs.

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
import { parseIdentity } from './identity-facts';
import { sendInviteRecoveryEmail } from './kratos';
import { confirmsInviteAddress, normalizeGroupOrder, shouldRefuseRecovery } from './access';
import { accessToStorage, choicesFromForm } from './access-rows';
import { GROUP_RE } from './access-groups';
import { IDENTITY_GROUPS } from './constants';
import { holdsElevatedRole, planGroupSave } from './gate';
import { buildGroupRegistry, isIdentityGroup, unconfiguredGroups } from './group-registry';
import { DEACTIVATE_STEP, RevokeError, revokeHydraSessions, revokeSubject } from './revoke';
import { removalBlock } from './admin-view';
import type { ClientManifest } from './manifests';
import type { Identity } from './types';

const USERNAME_RE = /^[a-z0-9]+(?:\.[a-z0-9]+)+$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

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
  | { kind: 'error'; message: string; partial?: true };

export interface ActionOutcome {
  actionResult?: ActionResult;
  refetch: boolean;
  formErrors?: Record<string, string>;
  mode?: 'read';
}

export interface ActionContext {
  id: string;
  identity: Identity;
  adminIdentityId: string;
  manifests: ClientManifest[];
  requirements?: readonly string[];
}

type ActionHandler = (fd: FormData, ctx: ActionContext) => Promise<ActionOutcome | Response>;

const ADMIN_RECOVERY_REFUSAL: ActionResult = {
  kind: 'error',
  message: 'A setup link for an admin cannot be made here. Whoever runs the server can set one up.',
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

  const clearUnconfigured = new Set(fd.getAll('clearUnconfigured').map(String));
  const keptUnconfigured = unconfiguredGroups(
    buildGroupRegistry(manifests, IDENTITY_GROUPS),
    parseIdentity(identity).groups,
  ).filter((g) => !clearUnconfigured.has(g));

  // planGroupSave decides from the stored identity, never from submitted checkboxes.
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

  // Only the targeted actions change these marks, so a save carries them over from the loaded identity.
  const existingAdmin = identity.metadata_admin?.admin;
  const existingPrerequisites = identity.metadata_admin?.prerequisites;
  const existingPasskeyNames = identity.metadata_admin?.passkeyNames;
  const groups = normalizeGroupOrder(groupPlan.groups);
  // Only a new elevation needs the second factor first, so people already elevated without one can still be edited and lowered.
  const after = { ...identity, metadata_admin: { ...identity.metadata_admin, groups, roles } };
  if (holdsElevatedRole(after, manifests) && !holdsElevatedRole(identity, manifests) && !parseIdentity(identity).hasSecondFactor) {
    return { actionResult: ELEVATED_SECOND_FACTOR_REQUIRED, refetch: false };
  }
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
  if (narrowsAccess(identity, groups, roles)) {
    const failure = await revokeGrants(id);
    if (failure) return { actionResult: failure, mode: 'read', refetch: true };
  }
  return { actionResult: { kind: 'updated', removed: groupPlan.removed }, mode: 'read', refetch: true };
}

/** An absent field keeps what is stored. */
interface SectionEdit {
  profile?: { username: string; email: string; displayName: string; recoveryEmail: string };
  household?: readonly string[];
  access?: { groups: readonly string[]; roles: Readonly<Record<string, string>> };
  remove?: readonly string[];
}

/** Rebuilds the whole form from what is stored, so every section passes saveAction's guards and none clobbers another. */
function sectionSave(ctx: ActionContext, edit: SectionEdit): Promise<ActionOutcome> {
  const { identity, manifests } = ctx;
  const registry = buildGroupRegistry(manifests, IDENTITY_GROUPS);
  const stored = parseIdentity(identity).groups;
  const storedUnconfigured = unconfiguredGroups(registry, stored);
  const desired = edit.access ? [...edit.access.groups] : [...stored];
  const roles = edit.access ? edit.access.roles : (identity.metadata_admin?.roles ?? {});
  const traits = identity.traits;

  const fd = new FormData();
  fd.set('username', edit.profile?.username ?? String(traits?.username ?? ''));
  fd.set('email', edit.profile?.email ?? String(traits?.email ?? ''));
  fd.set('displayName', edit.profile?.displayName ?? String(traits?.displayName ?? ''));
  fd.set('recoveryEmail', edit.profile?.recoveryEmail ?? String(traits?.recoveryEmail ?? ''));

  const household = edit.household
    ? edit.household.filter((g) => IDENTITY_GROUPS.includes(g))
    : desired.filter((g) => isIdentityGroup(registry, g));
  for (const g of household) fd.append('identityGroups', g);

  const removing = new Set(edit.remove ?? []);
  for (const g of desired) {
    if (isIdentityGroup(registry, g) || storedUnconfigured.includes(g) || removing.has(g)) continue;
    fd.append('accessGroups', g);
  }
  for (const g of storedUnconfigured) {
    if (removing.has(g) || (edit.access && !desired.includes(g))) fd.append('clearUnconfigured', g);
  }
  for (const g of removing) if (!GROUP_RE.test(g)) fd.append('clearNonCanonical', g);
  for (const [clientId, role] of Object.entries(roles)) fd.set(`role:${clientId}`, role);
  return saveAction(fd, ctx);
}

const TRAIT_FIELDS = ['username', 'email', 'displayName', 'recoveryEmail'] as const;

export function saveAccessAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const roles = { ...(ctx.identity.metadata_admin?.roles ?? {}) };
  const access = accessToStorage(ctx.manifests, choicesFromForm(fd), { groups: parseIdentity(ctx.identity).groups, roles });
  const [blocked] = access.unmet;
  if (blocked) {
    const app = ctx.manifests.find((m) => m.clientId === blocked.clientId);
    const others = blocked.sharedWith.join(', ') || 'another app';
    return Promise.resolve({
      actionResult: {
        kind: 'error',
        message:
          `${app?.clientName || blocked.clientId} shares the group "${blocked.group}" with ${others}, which you did not change, ` +
          `so access cannot be turned off for it alone. Turn off ${others} too, or leave it as it was. Nothing was saved.`,
      },
      refetch: false,
    });
  }
  return sectionSave(ctx, { access });
}

export function saveHouseholdAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  return sectionSave(ctx, { household: fd.getAll('identityGroups').map(String) });
}

export function saveProfileAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const [username, email, displayName, recoveryEmail] = TRAIT_FIELDS.map((k) => String(fd.get(k) ?? '').trim());
  return sectionSave(ctx, { profile: { username: username.toLowerCase(), email, displayName, recoveryEmail } });
}

export function removeGroupsAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  return sectionSave(ctx, { remove: fd.getAll('group').map(String).filter(Boolean) });
}

export async function markVerifiedAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  if (!ctx.identity.traits?.email) {
    return { actionResult: { kind: 'error', message: 'This person has no email address on file.' }, refetch: false };
  }
  if (!(await markEmailVerified(ctx.id, String(fd.get('email') ?? '')))) {
    return {
      actionResult: { kind: 'error', message: 'Their email address changed. Check the new address and try again.' },
      refetch: true,
    };
  }
  return { actionResult: { kind: 'email-verified' }, refetch: true };
}

export function nextPrerequisites(stored: readonly string[], known: readonly string[], submitted: readonly string[]): string[] {
  return [...stored.filter((n) => !known.includes(n)), ...known.filter((n) => submitted.includes(n))];
}

export async function setPrerequisitesAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const next = nextPrerequisites(
    ctx.identity.metadata_admin?.prerequisites ?? [],
    ctx.requirements ?? [],
    fd.getAll('prerequisite').map(String),
  );
  await patchPrerequisites(ctx.id, next);
  return { actionResult: { kind: 'prerequisites-saved' }, refetch: true };
}

export function narrowsAccess(identity: Identity, groups: readonly string[], roles: Record<string, string>): boolean {
  const stored = identity.metadata_admin;
  if ((stored?.groups ?? []).some((g) => !groups.includes(g))) return true;
  return Object.entries(stored?.roles ?? {}).some(([clientId, role]) => roles[clientId] !== role);
}

async function revokeGrants(id: string): Promise<ActionResult | null> {
  try {
    await revokeHydraSessions(id);
    return null;
  } catch (err) {
    return {
      kind: 'error',
      partial: true,
      message: `Saved, but their app sign-ins and access could not be ended: ${err instanceof Error ? err.message : 'unknown error'}`,
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
      actionResult: { kind: 'error', message: `The email could not be sent: ${err instanceof Error ? err.message : 'unknown error'}` },
      refetch: false,
    };
  }
}

export async function forceReloginAction(_fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const result = await revokeUserSessions(ctx.id);
  return { actionResult: { kind: 'revoked', result }, refetch: false };
}

function isActiveAdmin(identity: Identity): boolean {
  return parseIdentity(identity).isAdmin && identity.state !== 'inactive';
}

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
      actionResult: { kind: 'error', message: `${username} is the only admin who can sign in. Make someone else an admin first.` },
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
  // An admin must lose the marker first, where the last-admin guard runs; checked before the confirm text.
  if (parseIdentity(identity).isAdmin) {
    return {
      actionResult: {
        kind: 'error',
        message: 'An admin cannot be deleted. Remove their admin access first.',
      },
      refetch: false,
    };
  }
  const expected = identity.traits?.username ?? '';
  const confirm = String(fd.get('confirm') ?? '').trim();
  if (confirm !== expected) {
    return { actionResult: { kind: 'error', message: `Type the username (${expected}) to confirm.` }, refetch: false };
  }
  // Clear Hydra first: nothing reaches its tokens once the identity is gone, and a failed delete leaves it inactive.
  try {
    await revokeSubject(id, { deactivate: true });
  } catch (err) {
    // Past its first step the identity is already turned off.
    const landed = err instanceof RevokeError && err.step !== DEACTIVATE_STEP;
    return {
      actionResult: {
        kind: 'error',
        ...(landed && { partial: true as const }),
        message: `Not deleted: their sign-ins and app access could not be cleared first. ${err instanceof Error ? err.message : 'unknown error'}`,
      },
      refetch: landed,
    };
  }
  try {
    await deleteIdentity(id);
  } catch (err) {
    return {
      actionResult: {
        kind: 'error',
        partial: true,
        message: `Signed out and turned off, but not deleted: ${err instanceof Error ? err.message : 'unknown error'}`,
      },
      refetch: true,
    };
  }
  return new Response(null, { status: 303, headers: { Location: '/admin/users?deleted=1' } });
}

// Admins always step up at app sign-in, so the marker needs a second factor to step up with.
const SECOND_FACTOR_REQUIRED: ActionResult = {
  kind: 'error',
  message: 'Admins need an authenticator app or security key set up first.',
};

// Elevated app roles step up at sign-in too.
export const ELEVATED_ROLE_NEEDS_SECOND_FACTOR =
  "People with a role above an app's entry level need an authenticator app or security key set up first.";
const ELEVATED_SECOND_FACTOR_REQUIRED: ActionResult = { kind: 'error', message: ELEVATED_ROLE_NEEDS_SECOND_FACTOR };

const OWN_SECOND_FACTOR_REQUIRED: ActionResult = {
  kind: 'error',
  message: 'You cannot remove your own last authenticator app or security key. Set up another one first.',
};

export async function grantAdminAction(_fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const username = ctx.identity.traits?.username ?? ctx.id;
  if (!parseIdentity(ctx.identity).hasSecondFactor) {
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
  if (await leavesNoActiveAdmin(identity)) {
    return {
      actionResult: { kind: 'error', message: `${username} is the only admin who can sign in. Make someone else an admin first.` },
      refetch: false,
    };
  }
  await patchAdminMarker(id, false);
  const failure = await revokeGrants(id);
  if (failure) return { actionResult: failure, refetch: true };
  if (self) return new Response(null, { status: 303, headers: { Location: '/' } });
  return { actionResult: { kind: 'admin-revoked', username }, refetch: true };
}

// Kratos cannot admin-delete a passkey credential, so a stale form submitting one is refused here.
const PASSKEY_REFUSAL: ActionResult = {
  kind: 'error',
  message: 'A passkey can only be removed by its owner. Sign them out everywhere, then they can remove it in their own settings.',
};

export async function removeCredentialAction(fd: FormData, ctx: ActionContext): Promise<ActionOutcome> {
  const credType = String(fd.get('cred_type') ?? '').trim();
  if (credType === 'passkey') {
    return { actionResult: PASSKEY_REFUSAL, refetch: false };
  }
  if (!EVICTABLE_CREDENTIAL_TYPES.has(credType)) {
    return {
      actionResult: { kind: 'error', message: `That sign-in method cannot be removed here.` },
      refetch: false,
    };
  }
  const self = ctx.id === ctx.adminIdentityId;
  if (removalBlock(ctx.identity, credType, self, ctx.manifests)) {
    const refusal = self ? OWN_SECOND_FACTOR_REQUIRED : parseIdentity(ctx.identity).isAdmin ? SECOND_FACTOR_REQUIRED : ELEVATED_SECOND_FACTOR_REQUIRED;
    return { actionResult: refusal, refetch: false };
  }
  await deleteCredential(ctx.id, credType);
  // Someone else's lost method may have signed a session in, so end their sessions too. Your own stay.
  if (!self) {
    try {
      await revokeUserSessions(ctx.id);
    } catch (err) {
      const reason = err instanceof Error ? err.message : 'unknown error';
      return { actionResult: { kind: 'error', partial: true, message: `Removed, but their sessions could not be ended: ${reason}` }, refetch: true };
    }
  }
  return { actionResult: { kind: 'credential-removed', credType }, refetch: true };
}

/** One stdout JSON line per mutation: ids only, never emails, names or credential material. */
export function auditLine(actor: string, action: string, target: string, result: 'ok' | 'partial' | 'refused' | 'error'): void {
  console.log(JSON.stringify({ event: 'admin_action', action, actor, target, result }));
}

/** A partial error landed its write; any other error, or a save sent back with form errors, wrote nothing. */
function audited(action: string, handler: ActionHandler): ActionHandler {
  return async (fd, ctx) => {
    try {
      const outcome = await handler(fd, ctx);
      const r = outcome instanceof Response ? null : outcome.actionResult;
      const result = r === undefined ? 'refused' : r?.kind !== 'error' ? 'ok' : r.partial ? 'partial' : 'refused';
      auditLine(ctx.adminIdentityId, action, ctx.id, result);
      return outcome;
    } catch (err) {
      auditLine(ctx.adminIdentityId, action, ctx.id, 'error');
      throw err;
    }
  };
}

const HANDLERS: Record<string, ActionHandler> = {
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

export const ADMIN_ACTIONS: Record<string, ActionHandler> = Object.fromEntries(
  Object.entries(HANDLERS).map(([action, handler]) => [action, audited(action, handler)]),
);
