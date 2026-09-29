/**
 * admin-actions.test.ts — destructive-invariant tests for the admin POST
 * action handlers.
 *
 * Coverage (deliberately NOT re-testing lib-level primitives that already
 * have their own suites — gate.ts's planGroupSave, access.ts's
 * confirmsInviteAddress/shouldRefuseRecovery, revoke.ts):
 *   deleteAction:
 *   - admin-marked target refused, deleteIdentity never called (closes the
 *     delete-the-last-admin lockout; covers self-delete since self is admin)
 *   - wrong confirm refused, deleteIdentity never called
 *   - happy path: deleteIdentity called, 303 redirect Response returned
 *   - revokeSubject (deactivating) runs before deleteIdentity; a revoke failure
 *     keeps the identity; a delete failure after it is a neutral error
 *   saveAction:
 *   - a removed group or changed role revokes consent sessions after the write
 *   - an unchanged or widened save does not revoke; a revoke failure says the save stood
 *   - a stored group with no checkbox is kept unless its removal is ticked,
 *     and never counts toward the identity-group minimum
 *   deactivateAction:
 *   - self refused; the last active admin refused; a member needs no count
 *   revokeAdminAction:
 *   - self-demote refused, patchAdminMarker never called
 *   - last active admin refused (an inactive admin does not count), patchAdminMarker never called
 *   - happy path: patchAdminMarker(id, false) called, then consent sessions revoked
 *   removeCredentialAction:
 *   - non-allowlisted type refused, deleteCredential never called
 *   - passkey refused server-side (upstream 400 — Kratos cannot admin-delete
 *     it), deleteCredential never called
 *   - happy path: deleteCredential called
 *   - admin-marked target, and the acting admin, keep a totp or webauthn credential
 *   grantAdminAction:
 *   - refused without a totp or webauthn credential
 *   - happy path: patchAdminMarker(id, true) called
 *
 * Run: npx vitest run   (from portal/)
 */

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
} = vi.hoisted(() => ({
  updateIdentityMock: vi.fn(),
  revokeSubjectMock: vi.fn(),
  revokeConsentSessionsMock: vi.fn(),
  deleteIdentityMock: vi.fn(),
  listIdentitiesMock: vi.fn(),
  patchAdminMarkerMock: vi.fn(),
  deleteCredentialMock: vi.fn(),
  deactivateIdentityMock: vi.fn(),
}));

vi.mock('./admin', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./admin.js')>();
  return {
    ...actual,
    deleteIdentity: deleteIdentityMock,
    listIdentities: listIdentitiesMock,
    patchAdminMarker: patchAdminMarkerMock,
    updateIdentity: updateIdentityMock,
    deactivateIdentity: deactivateIdentityMock,
  };
});

vi.mock('./revoke', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./revoke.js')>();
  return { ...actual, revokeSubject: revokeSubjectMock, revokeConsentSessions: revokeConsentSessionsMock };
});

vi.mock('./admin-api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./admin-api.js')>();
  return { ...actual, deleteCredential: deleteCredentialMock };
});

import {
  deleteAction,
  deactivateAction,
  saveAction,
  revokeAdminAction,
  removeCredentialAction,
  grantAdminAction,
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
});

// ── deleteAction ──────────────────────────────────────────────────────────────

describe('deleteAction', () => {
  it('refuses an admin-marked target and never calls deleteIdentity', async () => {
    const identity = makeIdentity('root', true);
    const outcome = await deleteAction(fd({ confirm: 'root' }), makeCtx({ identity }));

    expect(deleteIdentityMock).not.toHaveBeenCalled();
    expect(outcome).not.toBeInstanceOf(Response);
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('error');
    expect(outcome.actionResult && 'message' in outcome.actionResult ? outcome.actionResult.message : '').toMatch(/revoke admin authority first/i);
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
      'Revoked and deactivated, but not deleted: kratos admin unavailable',
    );
  });
});

// ── saveAction ────────────────────────────────────────────────────────────────

describe('saveAction', () => {
  // Both groups are offered as access checkboxes, as the form renders them.
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

// ── revokeAdminAction ─────────────────────────────────────────────────────────

describe('revokeAdminAction', () => {
  it('refuses self-demote and never calls patchAdminMarker', async () => {
    const identity = makeIdentity('admin', true);
    const outcome = await revokeAdminAction(fd(), makeCtx({ id: 'admin-1', identity, adminIdentityId: 'admin-1' }));

    expect(patchAdminMarkerMock).not.toHaveBeenCalled();
    expect(outcome).not.toBeInstanceOf(Response);
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

// ── removeCredentialAction ──────────────────────────────────────────────────

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
    expect(outcome.actionResult.message).toMatch(/self-remove/);
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

// ── deactivateAction ────────────────────────────────────────────────────────

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

// ── grantAdminAction ─────────────────────────────────────────────────────────

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
