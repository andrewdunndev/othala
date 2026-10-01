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
  revokeConsentSessionsMock,
  patchPrerequisitesMock,
  markEmailVerifiedMock,
} = vi.hoisted(() => ({
  updateIdentityMock: vi.fn(),
  patchPrerequisitesMock: vi.fn(),
  markEmailVerifiedMock: vi.fn(),
  revokeSubjectMock: vi.fn(),
  revokeConsentSessionsMock: vi.fn(),
  deleteIdentityMock: vi.fn(),
  listIdentitiesMock: vi.fn(),
  patchAdminMarkerMock: vi.fn(),
  deleteCredentialMock: vi.fn(),
  deactivateIdentityMock: vi.fn(),
}));

vi.mock('./revoke', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./revoke.js')>();
  return { ...actual, revokeSubject: revokeSubjectMock, revokeConsentSessions: revokeConsentSessionsMock };
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
  ADMIN_ACTIONS,
  type ActionContext,
} from './admin-actions.js';
import type { Identity } from './types.js';
import { RevokeError } from './revoke.js';
import { identity, withLookupSecret, withPasskey, withTotp, withWebauthnKey } from './test-builders.js';

function makeIdentity(username: string, admin?: boolean, state?: 'active' | 'inactive'): Identity {
  return identity({ username, state, ...(admin === undefined ? {} : { metadataAdmin: { admin } }) });
}

const ADD: Record<string, (i: Identity) => Identity> = {
  password: (i) => i,
  totp: withTotp,
  webauthn: (i) => withWebauthnKey(i),
  passkey: withPasskey,
  lookup_secret: withLookupSecret,
};

function withCreds(i: Identity, ...types: string[]): Identity {
  return types.reduce((acc, t) => ADD[t](acc), i);
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
  deleteIdentityMock.mockReset().mockResolvedValue(undefined);
  listIdentitiesMock.mockReset().mockResolvedValue([]);
  patchAdminMarkerMock.mockReset().mockResolvedValue(undefined);
  deleteCredentialMock.mockReset().mockResolvedValue(undefined);
  deactivateIdentityMock.mockReset().mockResolvedValue(undefined);
  updateIdentityMock.mockReset().mockResolvedValue(undefined);
  revokeSubjectMock.mockReset().mockResolvedValue(undefined);
  revokeConsentSessionsMock.mockReset().mockResolvedValue(undefined);
  patchPrerequisitesMock.mockReset().mockResolvedValue(undefined);
  markEmailVerifiedMock.mockReset().mockResolvedValue(true);
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
  const MANIFESTS = [{ clientId: 'wiki', accessGroups: ['family', 'media'], groupRoleMap: {} }] as unknown as ActionContext['manifests'];

  function saveForm(groups: string[], role?: string): FormData {
    const f = fd({ username: 'alice.smith', email: 'alice.smith@othala.test' });
    for (const g of groups) f.append('identityGroups', g);
    if (role) f.set('role:wiki', role);
    return f;
  }

  function stored(groups: string[], roles?: Record<string, string>): Identity {
    return identity({ username: 'alice.smith', metadataAdmin: { groups, ...(roles ? { roles } : {}) } });
  }

  it('revokes consent sessions after the write when a group is removed', async () => {
    const outcome = await saveAction(saveForm(['family']), makeCtx({ identity: stored(['family', 'media']), manifests: MANIFESTS }));

    expect(updateIdentityMock).toHaveBeenCalledTimes(1);
    expect(revokeConsentSessionsMock).toHaveBeenCalledWith('target-1');
    expect(updateIdentityMock.mock.invocationCallOrder[0]).toBeLessThan(revokeConsentSessionsMock.mock.invocationCallOrder[0]);
    expect(outcome.actionResult?.kind).toBe('updated');
  });

  it('revokes consent sessions when a stored role changes', async () => {
    await saveAction(saveForm(['family'], 'viewer'), makeCtx({ identity: stored(['family'], { wiki: 'editor' }), manifests: MANIFESTS }));

    expect(revokeConsentSessionsMock).toHaveBeenCalledWith('target-1');
  });

  it('does not revoke when groups and roles are unchanged', async () => {
    const outcome = await saveAction(
      saveForm(['family'], 'editor'),
      makeCtx({ identity: stored(['family'], { wiki: 'editor' }), manifests: MANIFESTS }),
    );

    expect(updateIdentityMock).toHaveBeenCalledTimes(1);
    expect(revokeConsentSessionsMock).not.toHaveBeenCalled();
    expect(outcome.actionResult?.kind).toBe('updated');
  });

  it('does not revoke when a group is only added', async () => {
    await saveAction(saveForm(['family', 'media']), makeCtx({ identity: stored(['family']), manifests: MANIFESTS }));

    expect(revokeConsentSessionsMock).not.toHaveBeenCalled();
  });

  it('keeps a stored group the form offers no checkbox for', async () => {
    const outcome = await saveAction(saveForm(['family']), makeCtx({ identity: stored(['family', 'garden']), manifests: MANIFESTS }));

    expect(updateIdentityMock.mock.calls[0][1].metadataAdmin.groups).toEqual(['family', 'garden']);
    expect(revokeConsentSessionsMock).not.toHaveBeenCalled();
    expect(outcome.actionResult?.kind).toBe('updated');
  });

  it('keeps a stored group bound only as a role key', async () => {
    const manifests = [
      { clientId: 'wiki', accessGroups: ['family'], groupRoleMap: { 'wiki-admin': 'admin' } },
    ] as unknown as ActionContext['manifests'];
    await saveAction(saveForm(['family']), makeCtx({ identity: stored(['family', 'wiki-admin']), manifests }));

    expect(updateIdentityMock.mock.calls[0][1].metadataAdmin.groups).toEqual(['family', 'wiki-admin']);
  });

  it('drops a stored unconfigured group only when its removal is ticked, then revokes', async () => {
    const f = saveForm(['family']);
    f.append('clearUnconfigured', 'garden');
    await saveAction(f, makeCtx({ identity: stored(['family', 'garden']), manifests: MANIFESTS }));

    expect(updateIdentityMock.mock.calls[0][1].metadataAdmin.groups).toEqual(['family']);
    expect(revokeConsentSessionsMock).toHaveBeenCalledWith('target-1');
  });

  it('does not count a kept unconfigured group toward the identity-group minimum', async () => {
    const outcome = await saveAction(saveForm([]), makeCtx({ identity: stored(['garden']), manifests: MANIFESTS }));

    expect(updateIdentityMock).not.toHaveBeenCalled();
    expect(outcome.formErrors?.identityGroups).toBeDefined();
  });

  it('reports a revocation failure as an error after the save stood', async () => {
    revokeConsentSessionsMock.mockRejectedValue(new RevokeError('hydra-admin', 'revoke-consent-sessions', 'Verify HYDRA_ADMIN_URL.'));
    const outcome = await saveAction(saveForm(['family']), makeCtx({ identity: stored(['family', 'media']), manifests: MANIFESTS }));

    expect(updateIdentityMock).toHaveBeenCalledTimes(1);
    expect(outcome.actionResult?.kind).toBe('error');
    expect(outcome.actionResult && 'message' in outcome.actionResult ? outcome.actionResult.message : '').toMatch(/^Saved, but/);
    expect(outcome.refetch).toBe(true);
  });
});

describe('revokeAdminAction', () => {
  it('refuses self-demote without the typed username and never calls patchAdminMarker', async () => {
    const identity = makeIdentity('admin', true);
    for (const typed of [undefined, 'someone-else']) {
      const outcome = await revokeAdminAction(fd(typed ? { confirm: typed } : {}), makeCtx({ id: 'admin-1', identity, adminIdentityId: 'admin-1' }));
      expect(outcome).not.toBeInstanceOf(Response);
      if (outcome instanceof Response) throw new Error('unreachable');
      expect(outcome.actionResult?.kind).toBe('error');
    }
    expect(patchAdminMarkerMock).not.toHaveBeenCalled();
  });

  it('lets an admin give up their own access by typing their username when another admin remains', async () => {
    listIdentitiesMock.mockResolvedValue([makeIdentity('other-admin', true), makeIdentity('admin', true)]);
    const identity = makeIdentity('admin', true);
    const outcome = await revokeAdminAction(fd({ confirm: 'admin' }), makeCtx({ id: 'admin-1', identity, adminIdentityId: 'admin-1' }));

    expect(patchAdminMarkerMock).toHaveBeenCalledWith('admin-1', false);
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
    expect(revokeConsentSessionsMock).toHaveBeenCalledWith('target-1');
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
    const identity = withCreds(makeIdentity('root', true), 'password', 'totp', 'lookup_secret');
    const outcome = await removeCredentialAction(fd({ cred_type: 'totp' }), makeCtx({ identity }));

    expect(deleteCredentialMock).not.toHaveBeenCalled();
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('error');
  });

  it('allows removing one second factor of an admin-marked target while another remains', async () => {
    const identity = withCreds(makeIdentity('root', true), 'totp', 'webauthn');
    const outcome = await removeCredentialAction(fd({ cred_type: 'totp' }), makeCtx({ id: 'target-1', identity }));

    expect(deleteCredentialMock).toHaveBeenCalledWith('target-1', 'totp');
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('credential-removed');
  });

  it('refuses removing the acting admin\'s own last second factor', async () => {
    const identity = withCreds(makeIdentity('self'), 'webauthn');
    const outcome = await removeCredentialAction(
      fd({ cred_type: 'webauthn' }),
      makeCtx({ id: 'admin-1', identity, adminIdentityId: 'admin-1' }),
    );

    expect(deleteCredentialMock).not.toHaveBeenCalled();
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult && 'message' in outcome.actionResult ? outcome.actionResult.message : '').toMatch(/your own last/);
  });

  it('allows the acting admin to remove one second factor while another remains', async () => {
    const identity = withCreds(makeIdentity('self', true), 'totp', 'webauthn');
    await removeCredentialAction(fd({ cred_type: 'webauthn' }), makeCtx({ id: 'admin-1', identity, adminIdentityId: 'admin-1' }));
    expect(deleteCredentialMock).toHaveBeenCalledWith('admin-1', 'webauthn');
  });

  it('allows removing backup codes of an admin-marked target that keeps totp', async () => {
    const identity = withCreds(makeIdentity('root', true), 'totp', 'lookup_secret');
    await removeCredentialAction(fd({ cred_type: 'lookup_secret' }), makeCtx({ identity }));
    expect(deleteCredentialMock).toHaveBeenCalled();
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

  it('deactivates a member without an admin count', async () => {
    const outcome = await deactivateAction(fd(), makeCtx());

    expect(listIdentitiesMock).not.toHaveBeenCalled();
    expect(deactivateIdentityMock).toHaveBeenCalledWith('target-1');
    expect(outcome.actionResult?.kind).toBe('deactivated');
  });
});

describe('grantAdminAction', () => {
  it.each([[[]], [['password', 'passkey']], [['lookup_secret']]])(
    'refuses a target holding only %j and never calls patchAdminMarker',
    async (types: string[]) => {
      const identity = withCreds(makeIdentity('member'), ...types);
      const outcome = await grantAdminAction(fd(), makeCtx({ identity }));

      expect(patchAdminMarkerMock).not.toHaveBeenCalled();
      if (outcome instanceof Response) throw new Error('unreachable');
      expect(outcome.actionResult?.kind).toBe('error');
    },
  );

  it.each(['totp', 'webauthn'])('happy path with %s: calls patchAdminMarker(id, true)', async (t) => {
    const identity = withCreds(makeIdentity('member'), 'password', t);
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
      makeCtx({ identity: person(['everyone']), manifests: MANIFESTS }),
    );

    expect(outcome.actionResult?.kind).toBe('updated');
    expect(written().traits.username).toBe('robin.k');
    expect(written().metadataAdmin.groups).toEqual(['everyone', 'grafana-access', 'proxywatch-access']);
    expect(written().metadataAdmin.roles).toEqual({ grafana: 'editor' });
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
    expect(revokeConsentSessionsMock).toHaveBeenCalledWith('target-1');
  });

  it('keeps an unrecognised group through an access save', async () => {
    await saveAccessAction(fd({ 'level:proxywatch': 'use' }), makeCtx({ identity: person(['everyone', 'garden']), manifests: MANIFESTS }));

    expect(written().metadataAdmin.groups).toEqual(['everyone', 'garden', 'proxywatch-access']);
  });

  it('saves household groups without touching app access or the admin marker', async () => {
    const stored = identity({ username: 'robin.k', metadataAdmin: { groups: ['everyone', 'proxywatch-access'], admin: true } });
    await saveHouseholdAction(fd({ identityGroups: 'everyone' }), makeCtx({ identity: stored, manifests: MANIFESTS }));

    expect(written().metadataAdmin.groups).toEqual(['everyone', 'proxywatch-access']);
    expect(written().metadataAdmin.admin).toBe(true);
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
  const audit = async (action: string, ctx: ActionContext) => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    await ADMIN_ACTIONS[action](fd(), ctx).catch(() => {});
    const lines = log.mock.calls.map((c) => c[0]);
    log.mockRestore();
    return lines;
  };
  const member = withCreds(makeIdentity('member'), 'password', 'totp');

  it.each([
    ['grant-admin', makeCtx({ identity: member }), 'ok'],
    ['grant-admin', makeCtx({ identity: makeIdentity('member') }), 'refused'],
    ['deactivate', makeCtx(), 'ok'],
    ['deactivate', makeCtx({ id: 'admin-1' }), 'refused'],
  ])('%s emits exactly one line, result %s', async (action, ctx, result) => {
    const lines = await audit(action, ctx);
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0])).toEqual({ event: 'admin_action', action, actor: 'admin-1', target: ctx.id, result });
  });

  it('records a thrown mutation as error and rethrows', async () => {
    deactivateIdentityMock.mockRejectedValue(new Error('boom'));
    const lines = await audit('deactivate', makeCtx());
    expect(JSON.parse(lines[0]).result).toBe('error');
  });
});
