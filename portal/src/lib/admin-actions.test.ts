// Invariant: destructive admin actions refuse unsafe targets and never call the API after a failed guard.

import { describe, it, expect, vi, beforeEach } from 'vitest';

const {
  deleteIdentityMock,
  listIdentitiesMock,
  patchAdminMarkerMock,
  deleteCredentialMock,
  deactivateIdentityMock,
  updateIdentityMock,
  revokeSubjectMock,
  revokeHydraSessionsMock,
  patchPrerequisitesMock,
  markEmailVerifiedMock,
  getRecoveryLinkMock,
  getIdentityMock,
} = vi.hoisted(() => ({
  getIdentityMock: vi.fn(),
  getRecoveryLinkMock: vi.fn(),
  updateIdentityMock: vi.fn(),
  patchPrerequisitesMock: vi.fn(),
  markEmailVerifiedMock: vi.fn(),
  revokeSubjectMock: vi.fn(),
  revokeHydraSessionsMock: vi.fn(),
  deleteIdentityMock: vi.fn(),
  listIdentitiesMock: vi.fn(),
  patchAdminMarkerMock: vi.fn(),
  deleteCredentialMock: vi.fn(),
  deactivateIdentityMock: vi.fn(),
}));

vi.mock('./revoke', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./revoke.js')>();
  return { ...actual, revokeSubject: revokeSubjectMock, revokeHydraSessions: revokeHydraSessionsMock };
});

vi.mock('./admin-api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./admin-api.js')>();
  return {
    ...actual,
    deleteIdentity: deleteIdentityMock,
    listIdentities: listIdentitiesMock,
    patchAdminMarker: patchAdminMarkerMock,
    updateIdentity: updateIdentityMock,
    deactivateIdentity: deactivateIdentityMock,
    deleteCredential: deleteCredentialMock,
    patchPrerequisites: patchPrerequisitesMock,
    markEmailVerified: markEmailVerifiedMock,
    getRecoveryLink: getRecoveryLinkMock,
    getIdentity: getIdentityMock,
  };
});

import {
  deleteAction,
  deactivateAction,
  saveAction,
  saveAccessAction,
  saveHouseholdAction,
  saveProfileAction,
  removeGroupsAction,
  markVerifiedAction,
  setPrerequisitesAction,
  nextPrerequisites,
  revokeAdminAction,
  removeCredentialAction,
  grantAdminAction,
  issueRecoveryAction,
  ADMIN_ACTIONS,
  ENROLLMENT_TTL,
  auditLine,
  type ActionContext,
} from './admin-actions.js';
import type { Identity } from './types.js';
import { DEACTIVATE_STEP, RevokeError } from './revoke.js';
import { identity, manifest, withCredentials, withTotp, avatarOf } from './test-builders.js';

function makeIdentity(username: string, admin?: boolean, state?: 'active' | 'inactive'): Identity {
  return identity({ id: `id-${username}`, username, state, ...(admin === undefined ? {} : { metadataAdmin: { admin } }) });
}

function makeCtx(overrides: Partial<ActionContext> = {}): ActionContext {
  return {
    id: 'target-1',
    identity: makeIdentity('someone'),
    adminIdentityId: 'admin-1',
    manifests: [],
    ...overrides,
  };
}

function fd(entries: Record<string, string> = {}): FormData {
  const f = new FormData();
  for (const [k, v] of Object.entries(entries)) f.set(k, v);
  return f;
}

beforeEach(() => {
  getIdentityMock.mockReset().mockImplementation(async (id: string) => makeIdentity(`read-${id}`));
  deleteIdentityMock.mockReset().mockResolvedValue(undefined);
  listIdentitiesMock.mockReset().mockResolvedValue([]);
  patchAdminMarkerMock.mockReset().mockResolvedValue(undefined);
  deleteCredentialMock.mockReset().mockResolvedValue(undefined);
  deactivateIdentityMock.mockReset().mockResolvedValue(undefined);
  updateIdentityMock.mockReset().mockResolvedValue(undefined);
  revokeSubjectMock.mockReset().mockResolvedValue(undefined);
  revokeHydraSessionsMock.mockReset().mockResolvedValue(undefined);
  patchPrerequisitesMock.mockReset().mockResolvedValue(undefined);
  markEmailVerifiedMock.mockReset().mockResolvedValue(true);
  getRecoveryLinkMock.mockReset().mockResolvedValue({ recovery_link: 'https://sso.othala.test/r', recovery_code: '123456', expires_at: '' });
});

describe('deleteAction', () => {
  it('refuses an admin-marked target and never calls deleteIdentity', async () => {
    const identity = makeIdentity('root', true);
    const outcome = await deleteAction(fd({ confirm: 'root' }), makeCtx({ identity }));

    expect(deleteIdentityMock).not.toHaveBeenCalled();
    expect(outcome).not.toBeInstanceOf(Response);
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('error');
    expect(outcome.actionResult && 'message' in outcome.actionResult ? outcome.actionResult.message : '').toMatch(/remove their admin access first/i);
  });

  it('refuses a target who became an admin since the page loaded, and never calls deleteIdentity', async () => {
    getIdentityMock.mockResolvedValue(makeIdentity('promoted', true));
    const outcome = await deleteAction(fd({ confirm: 'promoted' }), makeCtx({ identity: makeIdentity('promoted') }));

    expect(getIdentityMock).toHaveBeenCalledWith('target-1');
    expect(revokeSubjectMock).not.toHaveBeenCalled();
    expect(deleteIdentityMock).not.toHaveBeenCalled();
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('error');
    expect(outcome.actionResult && 'message' in outcome.actionResult ? outcome.actionResult.message : '').toMatch(/remove their admin access first/i);
  });

  it('refuses a wrong confirm value and never calls deleteIdentity', async () => {
    const identity = makeIdentity('alice');
    const outcome = await deleteAction(fd({ confirm: 'not-alice' }), makeCtx({ identity }));

    expect(deleteIdentityMock).not.toHaveBeenCalled();
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('error');
  });

  it('happy path: calls deleteIdentity and returns a 303 redirect', async () => {
    const identity = makeIdentity('alice');
    const outcome = await deleteAction(fd({ confirm: 'alice' }), makeCtx({ id: 'target-1', identity }));

    expect(deleteIdentityMock).toHaveBeenCalledWith('target-1');
    expect(outcome).toBeInstanceOf(Response);
    if (!(outcome instanceof Response)) throw new Error('unreachable');
    expect(outcome.status).toBe(303);
    expect(outcome.headers.get('Location')).toBe('/admin/users?deleted=1');
  });

  it('revokes the subject before deleting it', async () => {
    const identity = makeIdentity('alice');
    await deleteAction(fd({ confirm: 'alice' }), makeCtx({ id: 'target-1', identity }));

    expect(revokeSubjectMock).toHaveBeenCalledWith('target-1', { deactivate: true });
    expect(revokeSubjectMock.mock.invocationCallOrder[0]).toBeLessThan(deleteIdentityMock.mock.invocationCallOrder[0]);
  });

  it('keeps the identity when revocation fails', async () => {
    revokeSubjectMock.mockRejectedValue(new RevokeError('hydra-admin', 'revoke-consent-sessions', 'Verify HYDRA_ADMIN_URL.'));
    const identity = makeIdentity('alice');
    const outcome = await deleteAction(fd({ confirm: 'alice' }), makeCtx({ id: 'target-1', identity }));

    expect(deleteIdentityMock).not.toHaveBeenCalled();
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('error');
    expect(outcome.actionResult && 'message' in outcome.actionResult ? outcome.actionResult.message : '').toMatch(/not deleted/i);
  });

  it('is not partial when the identity could not be turned off', async () => {
    revokeSubjectMock.mockRejectedValue(new RevokeError('kratos-admin', DEACTIVATE_STEP, 'Verify KRATOS_ADMIN_URL.'));
    const outcome = await deleteAction(fd({ confirm: 'alice' }), makeCtx({ identity: makeIdentity('alice') }));

    expect(deleteIdentityMock).not.toHaveBeenCalled();
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('error');
    expect(outcome.actionResult).not.toHaveProperty('partial');
  });

  it('reports a delete failure after revocation as an error, not a 500', async () => {
    deleteIdentityMock.mockRejectedValue(new Error('kratos admin unavailable'));
    const identity = makeIdentity('alice');
    const outcome = await deleteAction(fd({ confirm: 'alice' }), makeCtx({ id: 'target-1', identity }));

    expect(revokeSubjectMock).toHaveBeenCalledWith('target-1', { deactivate: true });
    expect(deleteIdentityMock).toHaveBeenCalledWith('target-1');
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('error');
    expect(outcome.actionResult && 'message' in outcome.actionResult ? outcome.actionResult.message : '').toBe(
      'Signed out and turned off, but not deleted: kratos admin unavailable',
    );
  });
});

describe('saveAction', () => {
  const MANIFESTS = [{ clientId: 'wiki', accessGroups: ['family', 'media'], roles: [], groupRoleMap: {} }] as unknown as ActionContext['manifests'];

  function saveForm(groups: string[], role?: string): FormData {
    const f = fd({ username: 'alice.smith', email: 'alice.smith@othala.test' });
    for (const g of groups) f.append('identityGroups', g);
    if (role) f.set('role:wiki', role);
    return f;
  }

  function stored(groups: string[], roles?: Record<string, string>): Identity {
    return identity({ username: 'alice.smith', metadataAdmin: { groups, ...(roles ? { roles } : {}) } });
  }

  it('ends app sign-ins after the write when a group is removed', async () => {
    const outcome = await saveAction(saveForm(['family']), makeCtx({ identity: stored(['family', 'media']), manifests: MANIFESTS }));

    expect(updateIdentityMock).toHaveBeenCalledTimes(1);
    expect(revokeHydraSessionsMock).toHaveBeenCalledWith('target-1');
    expect(updateIdentityMock.mock.invocationCallOrder[0]).toBeLessThan(revokeHydraSessionsMock.mock.invocationCallOrder[0]);
    expect(outcome.actionResult?.kind).toBe('updated');
  });

  it('ends app sign-ins when a stored role changes', async () => {
    await saveAction(saveForm(['family'], 'viewer'), makeCtx({ identity: stored(['family'], { wiki: 'editor' }), manifests: MANIFESTS }));

    expect(revokeHydraSessionsMock).toHaveBeenCalledWith('target-1');
  });

  it('does not revoke when groups and roles are unchanged', async () => {
    const outcome = await saveAction(
      saveForm(['family'], 'editor'),
      makeCtx({ identity: stored(['family'], { wiki: 'editor' }), manifests: MANIFESTS }),
    );

    expect(updateIdentityMock).toHaveBeenCalledTimes(1);
    expect(revokeHydraSessionsMock).not.toHaveBeenCalled();
    expect(outcome.actionResult?.kind).toBe('updated');
  });

  it('does not revoke when a group is only added', async () => {
    await saveAction(saveForm(['family', 'media']), makeCtx({ identity: stored(['family']), manifests: MANIFESTS }));

    expect(revokeHydraSessionsMock).not.toHaveBeenCalled();
  });

  it('keeps a stored group the form offers no checkbox for', async () => {
    const outcome = await saveAction(saveForm(['family']), makeCtx({ identity: stored(['family', 'garden']), manifests: MANIFESTS }));

    expect(updateIdentityMock.mock.calls[0][1].metadataAdmin.groups).toEqual(['family', 'garden']);
    expect(revokeHydraSessionsMock).not.toHaveBeenCalled();
    expect(outcome.actionResult?.kind).toBe('updated');
  });

  it('keeps a stored group bound only as a role key', async () => {
    const manifests = [
      { clientId: 'wiki', accessGroups: ['family'], roles: [], groupRoleMap: { 'wiki-admin': 'admin' } },
    ] as unknown as ActionContext['manifests'];
    await saveAction(saveForm(['family']), makeCtx({ identity: stored(['family', 'wiki-admin']), manifests }));

    expect(updateIdentityMock.mock.calls[0][1].metadataAdmin.groups).toEqual(['family', 'wiki-admin']);
  });

  it('drops a stored unconfigured group only when its removal is ticked, then revokes', async () => {
    const f = saveForm(['family']);
    f.append('clearUnconfigured', 'garden');
    await saveAction(f, makeCtx({ identity: stored(['family', 'garden']), manifests: MANIFESTS }));

    expect(updateIdentityMock.mock.calls[0][1].metadataAdmin.groups).toEqual(['family']);
    expect(revokeHydraSessionsMock).toHaveBeenCalledWith('target-1');
  });

  it('does not count a kept unconfigured group toward the identity-group minimum', async () => {
    const outcome = await saveAction(saveForm([]), makeCtx({ identity: stored(['garden']), manifests: MANIFESTS }));

    expect(updateIdentityMock).not.toHaveBeenCalled();
    expect(outcome.formErrors?.identityGroups).toBeDefined();
  });

  it('refuses a save that would keep a non-canonical group, leaving the identity unwritten', async () => {
    const outcome = await saveAction(saveForm(['family']), makeCtx({ identity: stored(['family', 'Bad Name']), manifests: MANIFESTS }));

    expect(updateIdentityMock).not.toHaveBeenCalled();
    expect(outcome.formErrors?.nonCanonicalGroups).toMatch(/Bad Name/);
    expect(outcome.refetch).toBe(false);
  });

  it('drops a non-canonical group only when its clear tick is posted', async () => {
    const f = saveForm(['family']);
    f.append('clearNonCanonical', 'Bad Name');
    await saveAction(f, makeCtx({ identity: stored(['family', 'Bad Name']), manifests: MANIFESTS }));

    expect(updateIdentityMock.mock.calls[0][1].metadataAdmin.groups).toEqual(['family']);
  });

  it('reports a revocation failure as an error after the save stood', async () => {
    revokeHydraSessionsMock.mockRejectedValue(new RevokeError('hydra-admin', 'revoke-consent-sessions', 'Verify HYDRA_ADMIN_URL.'));
    const outcome = await saveAction(saveForm(['family']), makeCtx({ identity: stored(['family', 'media']), manifests: MANIFESTS }));

    expect(updateIdentityMock).toHaveBeenCalledTimes(1);
    expect(outcome.actionResult?.kind).toBe('error');
    expect(outcome.actionResult && 'message' in outcome.actionResult ? outcome.actionResult.message : '').toMatch(/^Saved, but their app sign-ins and access could not be ended: /);
    expect(outcome.refetch).toBe(true);
  });

  describe('an elevated role needs a second factor', () => {
    const ranked = [manifest('wiki', ['admin', 'user'], { 'wiki-admin': 'admin', family: 'user' }, ['family'])];
    const save = (groups: string[], from: Identity) => saveAction(saveForm(groups), makeCtx({ identity: from, manifests: ranked }));

    it('refuses granting it to someone without one and writes nothing', async () => {
      const outcome = await save(['family', 'wiki-admin'], stored(['family']));

      expect(updateIdentityMock).not.toHaveBeenCalled();
      expect(outcome).toMatchObject({ actionResult: { kind: 'error', message: expect.stringMatching(/authenticator app or security key/) }, refetch: false });
    });

    it('grants it to someone with one', async () => {
      const outcome = await save(['family', 'wiki-admin'], withTotp(stored(['family'])));

      expect(updateIdentityMock).toHaveBeenCalledTimes(1);
      expect(outcome.actionResult?.kind).toBe('updated');
    });

    it('still saves other edits for someone who already holds it without one', async () => {
      const f = saveForm(['family'], 'admin');
      f.set('username', 'alice.jones');
      const outcome = await saveAction(f, makeCtx({ identity: stored(['family'], { wiki: 'admin' }), manifests: ranked }));

      expect(outcome.actionResult?.kind).toBe('updated');
      expect(updateIdentityMock.mock.calls[0][1].traits.username).toBe('alice.jones');
    });

    it('still lowers it for someone without one', async () => {
      const outcome = await save(['family'], stored(['family', 'wiki-admin']));

      expect(updateIdentityMock).toHaveBeenCalledTimes(1);
      expect(outcome.actionResult?.kind).toBe('updated');
    });
  });
});

describe('revokeAdminAction', () => {
  it('refuses self-demote without the typed username and never calls patchAdminMarker', async () => {
    listIdentitiesMock.mockResolvedValue([makeIdentity('other-admin', true), makeIdentity('admin', true)]);
    const identity = makeIdentity('admin', true);
    for (const typed of [undefined, 'someone-else']) {
      const outcome = await revokeAdminAction(fd(typed ? { confirm: typed } : {}), makeCtx({ id: 'admin-1', identity, adminIdentityId: 'admin-1' }));
      expect(outcome).not.toBeInstanceOf(Response);
      if (outcome instanceof Response) throw new Error('unreachable');
      expect(outcome.actionResult?.kind).toBe('error');
      expect(outcome.actionResult && 'message' in outcome.actionResult ? outcome.actionResult.message : '').toMatch(/Type your name/);
    }
    expect(patchAdminMarkerMock).not.toHaveBeenCalled();
  });

  it('lets an admin give up their own access by typing their username when another admin remains', async () => {
    listIdentitiesMock.mockResolvedValue([makeIdentity('other-admin', true), makeIdentity('admin', true)]);
    const identity = makeIdentity('admin', true);
    const outcome = await revokeAdminAction(fd({ confirm: 'admin' }), makeCtx({ id: 'admin-1', identity, adminIdentityId: 'admin-1' }));

    expect(patchAdminMarkerMock).toHaveBeenCalledWith('admin-1', false);
    expect(revokeHydraSessionsMock).toHaveBeenCalledWith('admin-1');
    expect(outcome).toBeInstanceOf(Response);
    expect((outcome as Response).status).toBe(303);
  });

  it('also accepts the display name for the typed confirm', async () => {
    listIdentitiesMock.mockResolvedValue([makeIdentity('other-admin', true), makeIdentity('admin', true)]);
    const named = identity({ username: 'admin', displayName: 'Amy Park', metadataAdmin: { admin: true } });
    await revokeAdminAction(fd({ confirm: 'Amy Park' }), makeCtx({ id: 'admin-1', identity: named, adminIdentityId: 'admin-1' }));

    expect(patchAdminMarkerMock).toHaveBeenCalledWith('admin-1', false);
  });

  it('still refuses the typed self-demote when it would leave no active admin', async () => {
    listIdentitiesMock.mockResolvedValue([makeIdentity('admin', true)]);
    const identity = makeIdentity('admin', true);
    const outcome = await revokeAdminAction(fd({ confirm: 'admin' }), makeCtx({ id: 'admin-1', identity, adminIdentityId: 'admin-1' }));

    expect(patchAdminMarkerMock).not.toHaveBeenCalled();
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('error');
  });

  it('refuses when the target is the last admin and never calls patchAdminMarker', async () => {
    listIdentitiesMock.mockResolvedValue([makeIdentity('sole-admin', true)]);
    const identity = makeIdentity('sole-admin', true);
    const outcome = await revokeAdminAction(fd(), makeCtx({ id: 'target-1', identity, adminIdentityId: 'admin-1' }));

    expect(patchAdminMarkerMock).not.toHaveBeenCalled();
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('error');
  });

  it('refuses when the only other admin is inactive', async () => {
    listIdentitiesMock.mockResolvedValue([makeIdentity('other-admin', true, 'inactive'), makeIdentity('target', true)]);
    const outcome = await revokeAdminAction(fd(), makeCtx({ identity: makeIdentity('target', true) }));

    expect(patchAdminMarkerMock).not.toHaveBeenCalled();
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('error');
  });

  it('happy path: revokes when another admin remains', async () => {
    listIdentitiesMock.mockResolvedValue([makeIdentity('other-admin', true), makeIdentity('target', true)]);
    const identity = makeIdentity('target', true);
    const outcome = await revokeAdminAction(fd(), makeCtx({ id: 'target-1', identity, adminIdentityId: 'admin-1' }));

    expect(patchAdminMarkerMock).toHaveBeenCalledWith('target-1', false);
    expect(revokeHydraSessionsMock).toHaveBeenCalledWith('target-1');
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('admin-revoked');
    expect(outcome.refetch).toBe(true);
  });
});

describe('removeCredentialAction', () => {
  it('refuses a non-allowlisted credential type and never calls deleteCredential', async () => {
    const outcome = await removeCredentialAction(fd({ cred_type: 'password' }), makeCtx());

    expect(deleteCredentialMock).not.toHaveBeenCalled();
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('error');
  });

  it('refuses passkey server-side (Kratos upstream cannot admin-delete it) and never calls deleteCredential', async () => {
    const outcome = await removeCredentialAction(fd({ cred_type: 'passkey' }), makeCtx());

    expect(deleteCredentialMock).not.toHaveBeenCalled();
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('error');
    if (outcome.actionResult?.kind !== 'error') throw new Error('unreachable');
    expect(outcome.actionResult.message).toMatch(/remove it in their own settings/);
  });

  it('happy path: calls deleteCredential with the identity id and type', async () => {
    const outcome = await removeCredentialAction(fd({ cred_type: 'webauthn' }), makeCtx({ id: 'target-1' }));

    expect(deleteCredentialMock).toHaveBeenCalledWith('target-1', 'webauthn');
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('credential-removed');
    expect(outcome.refetch).toBe(true);
  });

  it('refuses removing the last second factor of an admin-marked target', async () => {
    const identity = withCredentials(makeIdentity('root', true), 'password', 'totp', 'lookup_secret');
    const outcome = await removeCredentialAction(fd({ cred_type: 'totp' }), makeCtx({ identity }));

    expect(deleteCredentialMock).not.toHaveBeenCalled();
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('error');
  });

  it('allows removing one second factor of an admin-marked target while another remains', async () => {
    const identity = withCredentials(makeIdentity('root', true), 'totp', 'webauthn');
    const outcome = await removeCredentialAction(fd({ cred_type: 'totp' }), makeCtx({ id: 'target-1', identity }));

    expect(deleteCredentialMock).toHaveBeenCalledWith('target-1', 'totp');
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('credential-removed');
  });

  it('refuses removing the acting admin\'s own last second factor', async () => {
    const identity = withCredentials(makeIdentity('self'), 'webauthn');
    const outcome = await removeCredentialAction(
      fd({ cred_type: 'webauthn' }),
      makeCtx({ id: 'admin-1', identity, adminIdentityId: 'admin-1' }),
    );

    expect(deleteCredentialMock).not.toHaveBeenCalled();
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult && 'message' in outcome.actionResult ? outcome.actionResult.message : '').toMatch(/your own last/);
  });

  it('allows the acting admin to remove one second factor while another remains', async () => {
    const identity = withCredentials(makeIdentity('self', true), 'totp', 'webauthn');
    await removeCredentialAction(fd({ cred_type: 'webauthn' }), makeCtx({ id: 'admin-1', identity, adminIdentityId: 'admin-1' }));
    expect(deleteCredentialMock).toHaveBeenCalledWith('admin-1', 'webauthn');
  });

  it('allows removing backup codes of an admin-marked target that keeps totp', async () => {
    const identity = withCredentials(makeIdentity('root', true), 'totp', 'lookup_secret');
    await removeCredentialAction(fd({ cred_type: 'lookup_secret' }), makeCtx({ identity }));
    expect(deleteCredentialMock).toHaveBeenCalled();
  });

  it('refuses removing the last second factor of someone with an elevated app role', async () => {
    const manifests = [manifest('wiki', ['admin', 'user'], { 'wiki-admin': 'admin' }, ['family'])];
    const elevated = withCredentials(identity({ username: 'robin.k', metadataAdmin: { groups: ['family', 'wiki-admin'] } }), 'totp');
    const outcome = await removeCredentialAction(fd({ cred_type: 'totp' }), makeCtx({ identity: elevated, manifests }));

    expect(deleteCredentialMock).not.toHaveBeenCalled();
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome).toMatchObject({ actionResult: { kind: 'error', message: expect.stringMatching(/role above an app's entry level/) }, refetch: false });
  });

  it("ends another person's sessions after the removal", async () => {
    await removeCredentialAction(fd({ cred_type: 'totp' }), makeCtx({ id: 'target-1' }));

    expect(revokeSubjectMock).toHaveBeenCalledWith('target-1');
    expect(deleteCredentialMock.mock.invocationCallOrder[0]).toBeLessThan(revokeSubjectMock.mock.invocationCallOrder[0]);
  });

  it('keeps the acting admin signed in after removing their own method', async () => {
    const identity = withCredentials(makeIdentity('self', true), 'totp', 'webauthn');
    await removeCredentialAction(fd({ cred_type: 'webauthn' }), makeCtx({ id: 'admin-1', identity, adminIdentityId: 'admin-1' }));

    expect(deleteCredentialMock).toHaveBeenCalledWith('admin-1', 'webauthn');
    expect(revokeSubjectMock).not.toHaveBeenCalled();
  });

  it('reports a failed sign-out after the removal as a partial error, not a 500', async () => {
    revokeSubjectMock.mockRejectedValue(new RevokeError('kratos-admin', 'delete-sessions', 'Verify KRATOS_ADMIN_URL.'));
    const outcome = await removeCredentialAction(fd({ cred_type: 'totp' }), makeCtx({ id: 'target-1' }));

    expect(deleteCredentialMock).toHaveBeenCalledWith('target-1', 'totp');
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult).toMatchObject({ kind: 'error', partial: true, message: expect.stringMatching(/^Removed, but their sessions could not be ended: /) });
    expect(outcome.refetch).toBe(true);
  });
});

describe('issueRecoveryAction', () => {
  it('refuses an admin-marked target and never mints a link', async () => {
    const outcome = await issueRecoveryAction(fd({}), makeCtx({ identity: makeIdentity('boss', true) }));

    expect(getRecoveryLinkMock).not.toHaveBeenCalled();
    expect(outcome).toMatchObject({ actionResult: { kind: 'error', message: expect.stringMatching(/setup link for an admin/) }, refetch: false });
  });

  it('mints a 24h link for a non-admin target and returns it', async () => {
    getRecoveryLinkMock.mockResolvedValue({ recovery_link: 'https://sso.othala.test/r', recovery_code: '123456', expires_at: '2026-10-04T00:00:00Z' });
    const outcome = await issueRecoveryAction(fd({}), makeCtx());

    expect(getRecoveryLinkMock).toHaveBeenCalledTimes(1);
    expect(getRecoveryLinkMock).toHaveBeenCalledWith('target-1', ENROLLMENT_TTL);
    expect(outcome).toEqual({
      actionResult: { kind: 'recovery', url: 'https://sso.othala.test/r', code: '123456', expiresAt: '2026-10-04T00:00:00Z' },
      refetch: false,
    });
  });
});

describe('deactivateAction', () => {
  it('refuses self-deactivation and never calls deactivateIdentity', async () => {
    listIdentitiesMock.mockResolvedValue([makeIdentity('admin', true), makeIdentity('other', true)]);
    const outcome = await deactivateAction(fd(), makeCtx({ id: 'admin-1', identity: makeIdentity('admin', true), adminIdentityId: 'admin-1' }));

    expect(deactivateIdentityMock).not.toHaveBeenCalled();
    expect(outcome.actionResult?.kind).toBe('error');
  });

  it('refuses the last active admin, counting an inactive admin as absent', async () => {
    listIdentitiesMock.mockResolvedValue([makeIdentity('target', true), makeIdentity('dormant', true, 'inactive')]);
    const outcome = await deactivateAction(fd(), makeCtx({ identity: makeIdentity('target', true) }));

    expect(deactivateIdentityMock).not.toHaveBeenCalled();
    expect(outcome.actionResult?.kind).toBe('error');
  });

  it('deactivates an admin while another active admin remains', async () => {
    listIdentitiesMock.mockResolvedValue([makeIdentity('target', true), makeIdentity('other', true)]);
    const outcome = await deactivateAction(fd(), makeCtx({ identity: makeIdentity('target', true) }));

    expect(deactivateIdentityMock).toHaveBeenCalledWith('target-1');
    expect(outcome.actionResult?.kind).toBe('deactivated');
  });

  it('refuses a target who became the only admin since the page loaded', async () => {
    listIdentitiesMock.mockResolvedValue([makeIdentity('promoted', true)]);
    const outcome = await deactivateAction(fd(), makeCtx({ identity: makeIdentity('promoted') }));

    expect(deactivateIdentityMock).not.toHaveBeenCalled();
    expect(outcome.actionResult?.kind).toBe('error');
  });

  it('deactivates a member who is not an admin', async () => {
    listIdentitiesMock.mockResolvedValue([makeIdentity('someone'), makeIdentity('other-admin', true)]);
    const outcome = await deactivateAction(fd(), makeCtx());

    expect(deactivateIdentityMock).toHaveBeenCalledWith('target-1');
    expect(outcome.actionResult?.kind).toBe('deactivated');
  });
});

describe('grantAdminAction', () => {
  it.each([[[]], [['password', 'passkey']], [['lookup_secret']]])(
    'refuses a target holding only %j and never calls patchAdminMarker',
    async (types: string[]) => {
      const identity = withCredentials(makeIdentity('member'), ...types);
      const outcome = await grantAdminAction(fd(), makeCtx({ identity }));

      expect(patchAdminMarkerMock).not.toHaveBeenCalled();
      if (outcome instanceof Response) throw new Error('unreachable');
      expect(outcome.actionResult?.kind).toBe('error');
    },
  );

  it.each(['totp', 'webauthn'])('happy path with %s: calls patchAdminMarker(id, true)', async (t) => {
    const identity = withCredentials(makeIdentity('member'), 'password', t);
    const outcome = await grantAdminAction(fd(), makeCtx({ id: 'target-1', identity }));

    expect(patchAdminMarkerMock).toHaveBeenCalledWith('target-1', true);
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('admin-granted');
    expect(outcome.refetch).toBe(true);
  });
});

describe('person page sections', () => {
  const role = (name: string) => ({ name, description: '', claimEmit: {} });
  const MANIFESTS = [
    { clientId: 'grafana', accessGroups: ['grafana-access'], roles: [role('admin'), role('editor'), role('viewer')], groupRoleMap: { 'grafana-admin': 'admin' }, skipAccessCheck: false },
    { clientId: 'proxywatch', accessGroups: ['proxywatch-access'], roles: [], groupRoleMap: {}, skipAccessCheck: false },
  ] as unknown as ActionContext['manifests'];
  const person = (groups: string[], roles?: Record<string, string>) =>
    identity({ username: 'robin.k', email: 'robin@othala.test', metadataAdmin: { groups, ...(roles ? { roles } : {}) } });
  const written = () => updateIdentityMock.mock.calls[0][1];

  it('saves access: groups and overrides follow the chosen levels, traits stay as stored', async () => {
    const outcome = await saveAccessAction(
      fd({ 'level:grafana': 'editor', 'level:proxywatch': 'use' }),
      makeCtx({ identity: withTotp(person(['everyone'])), manifests: MANIFESTS }),
    );

    expect(outcome.actionResult?.kind).toBe('updated');
    expect(written().traits.username).toBe('robin.k');
    expect(written().metadataAdmin.groups).toEqual(['everyone', 'grafana-access', 'proxywatch-access']);
    expect(written().metadataAdmin.roles).toEqual({ grafana: 'editor' });
  });

  it('refuses an access level above the entry role for someone without a second factor and writes nothing', async () => {
    const outcome = await saveAccessAction(
      fd({ 'level:grafana': 'editor', 'level:proxywatch': 'use' }),
      makeCtx({ identity: person(['everyone']), manifests: MANIFESTS }),
    );

    expect(updateIdentityMock).not.toHaveBeenCalled();
    expect(outcome).toMatchObject({ actionResult: { kind: 'error', message: expect.stringMatching(/authenticator app or security key/) }, refetch: false });
  });

  it('names the shared group and saves nothing when No access cannot be stored', async () => {
    const shared = [
      MANIFESTS[0],
      { clientId: 'other', clientName: 'Other', accessGroups: ['grafana-access'], roles: [], groupRoleMap: {}, skipAccessCheck: false },
    ] as unknown as ActionContext['manifests'];
    const outcome = await saveAccessAction(
      fd({ 'level:grafana': 'none' }),
      makeCtx({ identity: person(['everyone', 'grafana-access']), manifests: shared }),
    );

    expect(outcome.actionResult?.kind).toBe('error');
    expect(JSON.stringify(outcome.actionResult)).toContain('grafana-access');
    expect(updateIdentityMock).not.toHaveBeenCalled();
  });

  it('removes a role group with the access, then revokes grants', async () => {
    await saveAccessAction(
      fd({ 'level:grafana': 'none' }),
      makeCtx({ identity: person(['everyone', 'grafana-access', 'grafana-admin']), manifests: MANIFESTS }),
    );

    expect(written().metadataAdmin.groups).toEqual(['everyone']);
    expect(revokeHydraSessionsMock).toHaveBeenCalledWith('target-1');
  });

  it('keeps an unrecognised group through an access save', async () => {
    await saveAccessAction(fd({ 'level:proxywatch': 'use' }), makeCtx({ identity: person(['everyone', 'garden']), manifests: MANIFESTS }));

    expect(written().metadataAdmin.groups).toEqual(['everyone', 'garden', 'proxywatch-access']);
  });

  it('saves household groups without touching app access', async () => {
    const stored = identity({ username: 'robin.k', metadataAdmin: { groups: ['everyone', 'proxywatch-access'] } });
    await saveHouseholdAction(fd({ identityGroups: 'everyone' }), makeCtx({ identity: stored, manifests: MANIFESTS }));

    expect(written().metadataAdmin.groups).toEqual(['everyone', 'proxywatch-access']);
  });

  it('drops an access group posted with the household groups', async () => {
    const form = new FormData();
    form.append('identityGroups', 'everyone');
    form.append('identityGroups', 'grafana-access');
    await saveHouseholdAction(form, makeCtx({ identity: person(['everyone']), manifests: MANIFESTS }));

    expect(written().metadataAdmin.groups).not.toContain('grafana-access');
  });

  it('saves the profile and leaves groups as stored', async () => {
    await saveProfileAction(
      fd({ username: 'Robin.K', email: 'a@othala.test', displayName: 'Robin', recoveryEmail: '' }),
      makeCtx({ identity: person(['everyone', 'grafana-access']), manifests: MANIFESTS }),
    );

    expect(written().traits).toMatchObject({ username: 'robin.k', email: 'a@othala.test', displayName: 'Robin' });
    expect(written().metadataAdmin.groups).toEqual(['everyone', 'grafana-access']);
  });

  it('removes an unrecognised group only when named, canonical or not', async () => {
    const f = fd();
    f.append('group', 'garden');
    f.append('group', 'Bad Name');
    await removeGroupsAction(f, makeCtx({ identity: person(['everyone', 'garden', 'Bad Name', 'proxywatch-access']), manifests: MANIFESTS }));

    expect(written().metadataAdmin.groups).toEqual(['everyone', 'proxywatch-access']);
  });
});

describe('prerequisites and verified email', () => {
  it('keeps marks for names no longer defined and follows the ticks for defined ones', () => {
    expect(nextPrerequisites(['tailscale', 'old'], ['tailscale', 'vpn'], ['vpn'])).toEqual(['old', 'vpn']);
    expect(nextPrerequisites([], ['tailscale'], ['tailscale', 'unknown'])).toEqual(['tailscale']);
  });

  it('patches only the prerequisites', async () => {
    const stored = identity({ username: 'a.b', metadataAdmin: { groups: ['everyone'], prerequisites: ['tailscale'] } });
    const f = fd();
    f.append('prerequisite', 'vpn');
    const outcome = await setPrerequisitesAction(f, makeCtx({ identity: stored, requirements: ['tailscale', 'vpn'] }));

    expect(patchPrerequisitesMock).toHaveBeenCalledWith('target-1', ['vpn']);
    expect(updateIdentityMock).not.toHaveBeenCalled();
    expect(outcome.actionResult?.kind).toBe('prerequisites-saved');
  });

  it('marks the email verified through the targeted write', async () => {
    const id = makeIdentity('someone');
    const outcome = await markVerifiedAction(fd({ email: id.traits.email }), makeCtx({ identity: id }));

    expect(markEmailVerifiedMock).toHaveBeenCalledWith('target-1', id.traits.email);
    expect(outcome.actionResult?.kind).toBe('email-verified');
  });

  it('refuses when the stored email is no longer the one the admin saw', async () => {
    markEmailVerifiedMock.mockResolvedValue(false);
    const outcome = await markVerifiedAction(fd({ email: 'old@othala.test' }), makeCtx({ identity: makeIdentity('someone') }));

    expect(markEmailVerifiedMock).toHaveBeenCalledWith('target-1', 'old@othala.test');
    expect(outcome.actionResult).toEqual({ kind: 'error', message: expect.stringContaining('changed') });
  });

  it('lets a rejected patch throw to the page, never reporting it verified', async () => {
    markEmailVerifiedMock.mockRejectedValue(new Error('Response returned an error code'));
    const id = makeIdentity('someone');

    await expect(markVerifiedAction(fd({ email: id.traits.email }), makeCtx({ identity: id }))).rejects.toThrow('error code');
  });
});

describe('admin action audit line', () => {
  const audit = async (action: string, ctx: ActionContext, form = fd()) => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    await ADMIN_ACTIONS[action](form, ctx).catch(() => {});
    const lines = log.mock.calls.map((c) => c[0]);
    log.mockRestore();
    return lines;
  };
  const member = withCredentials(makeIdentity('member'), 'password', 'totp');

  it.each([
    ['grant-admin', makeCtx({ identity: member }), 'ok'],
    ['grant-admin', makeCtx({ identity: makeIdentity('member') }), 'refused'],
    ['issue-recovery', makeCtx(), 'ok'],
    ['deactivate', makeCtx(), 'ok'],
    ['deactivate', makeCtx({ id: 'admin-1' }), 'refused'],
  ])('%s emits exactly one line, result %s', async (action, ctx, result) => {
    const lines = await audit(action, ctx);
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0])).toEqual({ event: 'admin_action', action, actor: 'admin-1', target: ctx.id, result });
  });

  describe('a write that landed before its sign-out failed is partial', () => {
    const proxywatch = [
      { clientId: 'proxywatch', accessGroups: ['proxywatch-access'], roles: [], groupRoleMap: {}, skipAccessCheck: false },
    ] as unknown as ActionContext['manifests'];
    const hydraDown = new RevokeError('hydra-admin', 'revoke-consent-sessions', 'Verify HYDRA_ADMIN_URL.');

    it.each([
      [
        'save-access', 'save-access',
        () => makeCtx({ identity: identity({ username: 'robin.k', metadataAdmin: { groups: ['everyone', 'proxywatch-access'] } }), manifests: proxywatch }),
        () => fd({ 'level:proxywatch': 'none' }),
      ],
      [
        'revoke-admin of another admin', 'revoke-admin',
        () => {
          listIdentitiesMock.mockResolvedValue([makeIdentity('root', true), makeIdentity('other', true)]);
          return makeCtx({ identity: makeIdentity('root', true) });
        },
        () => fd(),
      ],
      [
        'revoke-admin of yourself', 'revoke-admin',
        () => {
          listIdentitiesMock.mockResolvedValue([makeIdentity('admin', true), makeIdentity('other', true)]);
          return makeCtx({ id: 'admin-1', identity: makeIdentity('admin', true) });
        },
        () => fd({ confirm: 'admin' }),
      ],
      ['remove-credential', 'remove-credential', () => makeCtx(), () => fd({ cred_type: 'totp' })],
      ['delete when sign-out fails after deactivating', 'delete', () => makeCtx({ identity: makeIdentity('alice') }), () => fd({ confirm: 'alice' })],
      [
        'delete when removal fails after sign-out', 'delete',
        () => {
          revokeSubjectMock.mockResolvedValue(undefined);
          deleteIdentityMock.mockRejectedValue(new Error('kratos admin unavailable'));
          return makeCtx({ identity: makeIdentity('alice') });
        },
        () => fd({ confirm: 'alice' }),
      ],
    ])('%s', async (_label, action, ctx, form) => {
      revokeHydraSessionsMock.mockRejectedValue(hydraDown);
      revokeSubjectMock.mockRejectedValue(hydraDown);
      const c = ctx();
      const lines = await audit(action, c, form());
      expect(lines).toHaveLength(1);
      expect(JSON.parse(lines[0])).toEqual({ event: 'admin_action', action, actor: 'admin-1', target: c.id, result: 'partial' });
    });
  });

  it('writes the audit line as one JSON object of ids', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    auditLine('admin-1', 'create-user', 'new-1', 'ok');
    expect(log.mock.calls).toEqual([['{"event":"admin_action","action":"create-user","actor":"admin-1","target":"new-1","result":"ok"}']]);
    log.mockRestore();
  });

  it('records a thrown mutation as error and rethrows', async () => {
    deactivateIdentityMock.mockRejectedValue(new Error('boom'));
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    await expect(ADMIN_ACTIONS.deactivate(fd(), makeCtx())).rejects.toThrow('boom');
    expect(JSON.parse(log.mock.calls[0][0]).result).toBe('error');
    log.mockRestore();
  });
});

describe('app grants end on any roles-map or group-removal change', () => {
  const role = (name: string) => ({ name, description: '', claimEmit: {} });
  const MANIFESTS = [
    { clientId: 'grafana', accessGroups: ['grafana-access'], roles: [role('admin'), role('editor'), role('viewer')], groupRoleMap: { 'grafana-admin': 'admin' }, skipAccessCheck: false },
    { clientId: 'vault', accessGroups: ['grafana-admin'], roles: [], groupRoleMap: {}, skipAccessCheck: false },
  ] as unknown as ActionContext['manifests'];
  const person = (groups: string[], roles?: Record<string, string>) =>
    identity({ username: 'robin.k', email: 'robin@othala.test', metadataAdmin: { groups, ...(roles ? { roles } : {}) } });
  const form = (groups: string[], roles: Record<string, string> = {}) => {
    const f = fd({ username: 'robin.k', email: 'robin@othala.test' });
    for (const g of groups) f.append('identityGroups', g);
    for (const [k, v] of Object.entries(roles)) f.set(`role:${k}`, v);
    return f;
  };

  it('revokes when a demotion is stored as a new override while a shared group stays', async () => {
    const outcome = await saveAccessAction(
      fd({ 'level:grafana': 'editor', 'level:vault': 'use' }),
      makeCtx({ identity: withTotp(person(['everyone', 'grafana-access', 'grafana-admin'])), manifests: MANIFESTS }),
    );

    expect(updateIdentityMock.mock.calls[0][1].metadataAdmin.roles).toEqual({ grafana: 'editor' });
    expect(updateIdentityMock.mock.calls[0][1].metadataAdmin.groups).toContain('grafana-admin');
    expect(revokeHydraSessionsMock).toHaveBeenCalledWith('target-1');
    expect(outcome.actionResult?.kind).toBe('updated');
  });

  it('revokes when an override is added', async () => {
    await saveAction(form(['everyone', 'grafana-access'], { grafana: 'viewer' }), makeCtx({ identity: person(['everyone', 'grafana-access']), manifests: MANIFESTS }));

    expect(revokeHydraSessionsMock).toHaveBeenCalledWith('target-1');
  });

  it('revokes when an override is removed', async () => {
    await saveAction(form(['everyone', 'grafana-access']), makeCtx({ identity: person(['everyone', 'grafana-access'], { grafana: 'viewer' }), manifests: MANIFESTS }));

    expect(revokeHydraSessionsMock).toHaveBeenCalledWith('target-1');
  });

  it('revokes when a group is removed', async () => {
    await saveAction(form(['everyone']), makeCtx({ identity: person(['everyone', 'grafana-access']), manifests: MANIFESTS }));

    expect(revokeHydraSessionsMock).toHaveBeenCalledWith('target-1');
  });

  it('does not revoke when a group is only added', async () => {
    const outcome = await saveAction(
      (() => {
        const f = form(['everyone']);
        f.append('accessGroups', 'grafana-access');
        return f;
      })(),
      makeCtx({ identity: person(['everyone']), manifests: MANIFESTS }),
    );

    expect(updateIdentityMock.mock.calls[0][1].metadataAdmin.groups).toContain('grafana-access');
    expect(revokeHydraSessionsMock).not.toHaveBeenCalled();
    expect(outcome.actionResult?.kind).toBe('updated');
  });
});

describe('what a save does not render', () => {
  const MANIFESTS = [{ clientId: 'wiki', accessGroups: ['family'], roles: [], groupRoleMap: {}, skipAccessCheck: false }] as unknown as ActionContext['manifests'];
  const person = (roles?: Record<string, string>) =>
    identity({ username: 'robin.k', email: 'robin@othala.test', metadataAdmin: { groups: ['everyone'], ...(roles ? { roles } : {}) } });
  const form = (extra: Record<string, string> = {}) => fd({ username: 'robin.k', email: 'robin@othala.test', ...extra });
  const withGroup = (f: FormData) => (f.append('identityGroups', 'everyone'), f);
  const written = () => updateIdentityMock.mock.calls[0][1].metadataAdmin;

  it('keeps an override for an app with no served manifest, and does not end grants for it', async () => {
    const outcome = await saveAction(withGroup(form()), makeCtx({ identity: person({ ghost: 'editor' }), manifests: MANIFESTS }));

    expect(written().roles).toEqual({ ghost: 'editor' });
    expect(revokeHydraSessionsMock).not.toHaveBeenCalled();
    expect(outcome.actionResult?.kind).toBe('updated');
  });

  it('keeps every override on a cold start with no manifests served', async () => {
    await saveAction(withGroup(form()), makeCtx({ identity: person({ wiki: 'editor', ghost: 'viewer' }), manifests: [] }));

    expect(written().roles).toEqual({ wiki: 'editor', ghost: 'viewer' });
    expect(revokeHydraSessionsMock).not.toHaveBeenCalled();
  });

  it('keeps an unserved override through a section save that posts it back', async () => {
    await saveProfileAction(
      fd({ username: 'robin.k', email: 'robin@othala.test', displayName: 'Robin', recoveryEmail: '' }),
      makeCtx({ identity: person({ ghost: 'editor' }), manifests: MANIFESTS }),
    );

    expect(written().roles).toEqual({ ghost: 'editor' });
  });

  it('removes an unserved override only on an explicit clear, and ends grants then', async () => {
    const f = withGroup(form());
    f.append('clearRoles', 'ghost');
    await saveAction(f, makeCtx({ identity: person({ ghost: 'editor', other: 'x' }), manifests: MANIFESTS }));

    expect(written().roles).toEqual({ other: 'x' });
    expect(revokeHydraSessionsMock).toHaveBeenCalledWith('target-1');
  });

  it('still takes the submitted value for a served app', async () => {
    await saveAction(withGroup(form({ 'role:wiki': 'viewer' })), makeCtx({ identity: person({ wiki: 'editor', ghost: 'x' }), manifests: MANIFESTS }));

    expect(written().roles).toEqual({ wiki: 'viewer', ghost: 'x' });
  });

  it('hands updateIdentity only what it edits; admin, avatar and passkey names are the update\'s to carry', async () => {
    const stale = identity({ username: 'robin.k', metadataAdmin: { groups: ['family'], admin: true, avatar: avatarOf('png'), passkeyNames: { k: 'Key' } } });
    await saveAction(withGroup(form()), makeCtx({ identity: stale, manifests: MANIFESTS }));

    expect(written()).not.toHaveProperty('admin');
    expect(written()).not.toHaveProperty('avatar');
    expect(written()).not.toHaveProperty('passkeyNames');
  });
});

describe('clearRolesAction', () => {
  const MANIFESTS = [{ clientId: 'wiki', accessGroups: ['family'], roles: [], groupRoleMap: {}, skipAccessCheck: false }] as unknown as ActionContext['manifests'];
  const person = identity({ username: 'robin.k', email: 'robin@othala.test', metadataAdmin: { groups: ['everyone'], roles: { wiki: 'editor', ghost: 'viewer' } } });

  it('removes the named override for an app with no served manifest and ends grants', async () => {
    const f = new FormData();
    f.append('clearRole', 'ghost');
    const outcome = await ADMIN_ACTIONS['clear-roles'](f, makeCtx({ identity: person, manifests: MANIFESTS }));

    expect(updateIdentityMock.mock.calls[0][1].metadataAdmin.roles).toEqual({ wiki: 'editor' });
    expect(revokeHydraSessionsMock).toHaveBeenCalledWith('target-1');
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('updated');
  });

  it('leaves the override of a served app alone', async () => {
    const f = new FormData();
    f.append('clearRole', 'wiki');
    await ADMIN_ACTIONS['clear-roles'](f, makeCtx({ identity: person, manifests: MANIFESTS }));

    expect(updateIdentityMock.mock.calls[0][1].metadataAdmin.roles).toEqual({ wiki: 'editor', ghost: 'viewer' });
  });
});

describe('admin changes are serialized and the last-admin count is taken inside the lock', () => {
  const tick = () => new Promise((r) => setTimeout(r, 5));
  type Row = { id: string; admin: boolean; state: 'active' | 'inactive' };
  let rows: Row[];
  const asIdentity = (r: Row) => identity({ id: r.id, username: `${r.id}.person`, state: r.state, metadataAdmin: { admin: r.admin } });
  const rowOf = (id: string) => rows.find((r) => r.id === id)!;
  const ctxFor = (target: string, actor: string): ActionContext => makeCtx({ id: target, adminIdentityId: actor, identity: asIdentity(rowOf(target)) });
  const outcomeKind = (o: unknown) => (o instanceof Response ? 'response' : (o as { actionResult?: { kind: string } }).actionResult?.kind);

  beforeEach(() => {
    rows = [
      { id: 'aaa', admin: true, state: 'active' },
      { id: 'bbb', admin: true, state: 'active' },
    ];
    listIdentitiesMock.mockReset().mockImplementation(async () => {
      await tick();
      return rows.map(asIdentity);
    });
    patchAdminMarkerMock.mockReset().mockImplementation(async (id: string, grant: boolean) => {
      await tick();
      rowOf(id).admin = grant;
    });
    deactivateIdentityMock.mockReset().mockImplementation(async (id: string) => {
      await tick();
      rowOf(id).state = 'inactive';
    });
  });

  it('two admins revoking each other at once leave one admin', async () => {
    const kinds = (await Promise.all([revokeAdminAction(fd(), ctxFor('bbb', 'aaa')), revokeAdminAction(fd(), ctxFor('aaa', 'bbb'))])).map(outcomeKind);

    expect(kinds.sort()).toEqual(['admin-revoked', 'error']);
    expect(rows.filter((r) => r.admin)).toHaveLength(1);
  });

  it('two admins deactivating each other at once leave one who can sign in', async () => {
    const kinds = (await Promise.all([deactivateAction(fd(), ctxFor('bbb', 'aaa')), deactivateAction(fd(), ctxFor('aaa', 'bbb'))])).map(outcomeKind);

    expect(kinds.sort()).toEqual(['deactivated', 'error']);
    expect(rows.filter((r) => r.admin && r.state === 'active')).toHaveLength(1);
  });

  it('a revoke and a deactivate aimed at the two admins at once leave one', async () => {
    await Promise.all([revokeAdminAction(fd(), ctxFor('bbb', 'aaa')), deactivateAction(fd(), ctxFor('aaa', 'bbb'))]);

    expect(rows.filter((r) => r.admin && r.state === 'active')).toHaveLength(1);
  });

  it('a save racing a revoke-admin does not restore the marker', async () => {
    // updateIdentity writes the marker back from the value it read, so an unqueued save lands after the revoke and undoes it.
    updateIdentityMock.mockReset().mockImplementation(async (id: string) => {
      const read = rowOf(id).admin;
      for (let i = 0; i < 4; i++) await tick();
      rowOf(id).admin = read;
    });
    const form = fd({ username: 'aaa.person', email: 'aaa.person@othala.test' });
    form.append('identityGroups', 'family');

    await Promise.all([saveAction(form, ctxFor('aaa', 'bbb')), revokeAdminAction(fd(), ctxFor('aaa', 'bbb'))]);

    expect(rowOf('aaa').admin).toBe(false);
  });

  it('a failed action does not hold the lock for the next one', async () => {
    patchAdminMarkerMock.mockRejectedValueOnce(new Error('kratos down'));
    await expect(revokeAdminAction(fd(), ctxFor('bbb', 'aaa'))).rejects.toThrow('kratos down');
    const next = await revokeAdminAction(fd(), ctxFor('bbb', 'aaa'));

    expect(outcomeKind(next)).toBe('admin-revoked');
  });

  it('deletes run one at a time', async () => {
    rows.push({ id: 'ccc', admin: false, state: 'active' }, { id: 'ddd', admin: false, state: 'active' });
    const trace: string[] = [];
    revokeSubjectMock.mockReset().mockImplementation(async (id: string) => {
      trace.push(`start ${id}`);
      await tick();
    });
    deleteIdentityMock.mockReset().mockImplementation(async (id: string) => {
      await tick();
      trace.push(`end ${id}`);
    });
    const del = (id: string) => deleteAction(fd({ confirm: `${id}.person` }), ctxFor(id, 'aaa'));
    await Promise.all([del('ccc'), del('ddd')]);

    expect(trace).toEqual(['start ccc', 'end ccc', 'start ddd', 'end ddd']);
  });
});
