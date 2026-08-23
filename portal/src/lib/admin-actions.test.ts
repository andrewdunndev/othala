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
 *   revokeAdminAction:
 *   - self-demote refused, patchAdminMarker never called
 *   - last-admin refused (listIdentities → adminCount 1), patchAdminMarker never called
 *   - happy path: patchAdminMarker(id, false) called
 *   removeCredentialAction:
 *   - non-allowlisted type refused, deleteCredential never called
 *   - passkey refused server-side (upstream 400 — Kratos cannot admin-delete
 *     it), deleteCredential never called
 *   - happy path: deleteCredential called
 *   grantAdminAction:
 *   - happy path: patchAdminMarker(id, true) called
 *
 * Run: npx vitest run   (from portal/)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const { deleteIdentityMock, listIdentitiesMock, patchAdminMarkerMock, deleteCredentialMock } = vi.hoisted(() => ({
  deleteIdentityMock: vi.fn(),
  listIdentitiesMock: vi.fn(),
  patchAdminMarkerMock: vi.fn(),
  deleteCredentialMock: vi.fn(),
}));

vi.mock('./admin', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./admin.js')>();
  return { ...actual, deleteIdentity: deleteIdentityMock, listIdentities: listIdentitiesMock, patchAdminMarker: patchAdminMarkerMock };
});

vi.mock('./admin-api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./admin-api.js')>();
  return { ...actual, deleteCredential: deleteCredentialMock };
});

import { deleteAction, revokeAdminAction, removeCredentialAction, grantAdminAction, type ActionContext } from './admin-actions.js';
import type { Identity } from './types.js';

function makeIdentity(username: string, admin?: boolean): Identity {
  return {
    id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    schema_id: 'family',
    schema_url: 'http://kratos:4434/schemas/family',
    state: 'active',
    traits: { username, email: `${username}@example.com` },
    metadata_admin: admin === undefined ? undefined : ({ admin } as Identity['metadata_admin']),
  };
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

  it('happy path: revokes when another admin remains', async () => {
    listIdentitiesMock.mockResolvedValue([makeIdentity('other-admin', true), makeIdentity('target', true)]);
    const identity = makeIdentity('target', true);
    const outcome = await revokeAdminAction(fd(), makeCtx({ id: 'target-1', identity, adminIdentityId: 'admin-1' }));

    expect(patchAdminMarkerMock).toHaveBeenCalledWith('target-1', false);
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
});

// ── grantAdminAction ─────────────────────────────────────────────────────────

describe('grantAdminAction', () => {
  it('happy path: calls patchAdminMarker(id, true)', async () => {
    const outcome = await grantAdminAction(fd(), makeCtx({ id: 'target-1' }));

    expect(patchAdminMarkerMock).toHaveBeenCalledWith('target-1', true);
    if (outcome instanceof Response) throw new Error('unreachable');
    expect(outcome.actionResult?.kind).toBe('admin-granted');
    expect(outcome.refetch).toBe(true);
  });
});
