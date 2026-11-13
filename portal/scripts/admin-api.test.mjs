// Invariant: Kratos admin API wrappers send the right requests and fail closed on error.

import { test, beforeEach, afterEach } from 'vitest';
import assert from 'node:assert/strict';
import { identity, avatarOf } from '../src/lib/test-builders.ts';
import { createIdentity, deleteCredential, getIdentity, getRecoveryLink, listIdentities, listSessions, patchAdminMarker, patchPrerequisites, revokeSession, updateIdentity } from '../src/lib/admin-api.ts';
import { MetadataAdminError } from '../src/lib/metadata-admin.ts';

function kratosIdentity(fields) {
  return { ...identity({ id: fields.id }), ...fields };
}

const realFetch = globalThis.fetch;
let capturedCalls = [];

function mockFetchSequence(responses) {
  capturedCalls = [];
  let i = 0;
  globalThis.fetch = async (url, opts) => {
    const r = responses[i] ?? responses[responses.length - 1];
    i++;
    capturedCalls.push({ url: String(url), opts });
    return new Response(JSON.stringify(r.body), { status: r.status ?? 200, headers: { 'Content-Type': 'application/json' } });
  };
}

const mockFetch = (body, status = 200) => mockFetchSequence([{ body, status }]);

const RECOVERY = { recovery_link: 'https://example.com/recovery/abc', recovery_code: '654321', expires_at: '2026-06-01T00:00:00Z' };

beforeEach(() => {
  mockFetch(kratosIdentity({ id: 'mock-id', traits: {}, metadata_admin: {} }));
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

test('getIdentity: URL-encodes special characters in id', async () => {
  mockFetch(kratosIdentity({ id: 'id/with/slash', traits: {} }));
  await getIdentity('id/with/slash');
  assert.match(capturedCalls[0].url, /id%2Fwith%2Fslash/);
});

test('getRecoveryLink: POSTs identity_id to /admin/recovery/code', async () => {
  mockFetch(RECOVERY);
  await getRecoveryLink('user-123');
  assert.equal(capturedCalls[0].opts.method, 'POST');
  assert.match(capturedCalls[0].url, /\/admin\/recovery\/code$/);
  assert.equal(JSON.parse(capturedCalls[0].opts.body).identity_id, 'user-123');
});

test('getRecoveryLink: defaults expires_in to "1h"', async () => {
  mockFetch(RECOVERY);
  await getRecoveryLink('user-123');
  assert.equal(JSON.parse(capturedCalls[0].opts.body).expires_in, '1h');
});

test('getRecoveryLink: passes explicit expires_in', async () => {
  mockFetch(RECOVERY);
  await getRecoveryLink('user-123', '24h');
  assert.equal(JSON.parse(capturedCalls[0].opts.body).expires_in, '24h');
});

test('getRecoveryLink: returns recovery_link + recovery_code + expires_at', async () => {
  mockFetch(RECOVERY);
  const result = await getRecoveryLink('user-123');
  assert.equal(result.recovery_link, 'https://example.com/recovery/abc');
  assert.equal(result.recovery_code, '654321');
  assert.equal(result.expires_at, '2026-06-01T00:00:00.000Z');
});

test('getIdentity and getRecoveryLink throw on non-2xx', async () => {
  for (const status of [400, 403, 500]) {
    mockFetch({ error: { code: status } }, status);
    await assert.rejects(() => getIdentity('user-id'), (err) => err.response?.status === status);
    await assert.rejects(() => getRecoveryLink('user-id'), (err) => err.response?.status === status);
  }
});

test('patchAdminMarker/grant: GET then PATCH add /metadata_admin when metadata_admin absent', async () => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'u1', traits: {}, schema_id: 'family', state: 'active', metadata_admin: null }) },
    { body: kratosIdentity({ id: 'u1', traits: {}, metadata_admin: { admin: true } }) },
  ]);
  await patchAdminMarker('u1', true);
  assert.equal(capturedCalls.length, 2);
  assert.match(capturedCalls[0].url, /\/admin\/identities\/u1/);
  assert.equal(capturedCalls[0].opts.method, 'GET');
  assert.equal(capturedCalls[1].opts.method, 'PATCH');
  assert.deepEqual(JSON.parse(capturedCalls[1].opts.body), [{ op: 'add', path: '/metadata_admin', value: { admin: true } }]);
});

test('patchAdminMarker/grant: add /metadata_admin/admin when metadata_admin exists without admin key', async () => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'u2', traits: {}, metadata_admin: { groups: ['family'] } }) },
    { body: kratosIdentity({ id: 'u2', traits: {}, metadata_admin: { groups: ['family'], admin: true } }) },
  ]);
  await patchAdminMarker('u2', true);
  assert.deepEqual(JSON.parse(capturedCalls[1].opts.body), [{ op: 'add', path: '/metadata_admin/admin', value: true }]);
});

test('patchAdminMarker/grant: replace /metadata_admin/admin when admin key already exists', async () => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'u3', traits: {}, metadata_admin: { groups: ['family'], admin: false } }) },
    { body: kratosIdentity({ id: 'u3', traits: {}, metadata_admin: { groups: ['family'], admin: true } }) },
  ]);
  await patchAdminMarker('u3', true);
  assert.deepEqual(JSON.parse(capturedCalls[1].opts.body), [{ op: 'replace', path: '/metadata_admin/admin', value: true }]);
});

test('patchAdminMarker/revoke: GET then PATCH remove when admin key present', async () => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'u4', traits: {}, metadata_admin: { groups: ['family'], admin: true } }) },
    { body: kratosIdentity({ id: 'u4', traits: {}, metadata_admin: { groups: ['family'] } }) },
  ]);
  await patchAdminMarker('u4', false);
  assert.equal(capturedCalls.length, 2);
  assert.equal(capturedCalls[1].opts.method, 'PATCH');
  assert.deepEqual(JSON.parse(capturedCalls[1].opts.body), [{ op: 'remove', path: '/metadata_admin/admin' }]);
});

test('patchAdminMarker/revoke: no PATCH when the admin key or metadata_admin is absent', async () => {
  for (const metadata_admin of [{ groups: ['family'] }, null]) {
    mockFetchSequence([{ body: kratosIdentity({ id: 'u5', traits: {}, metadata_admin }) }]);
    await patchAdminMarker('u5', false);
    assert.equal(capturedCalls.length, 1);
  }
});

test('updateIdentity keeps a deactivated person deactivated', async () => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'u6', traits: {}, schema_id: 'family', state: 'inactive', metadata_admin: {} }) },
    { body: kratosIdentity({ id: 'u6', traits: {}, state: 'inactive' }) },
  ]);
  await updateIdentity('u6', { traits: { username: 'robin' }, metadataAdmin: { groups: ['family'] } });
  assert.equal(capturedCalls[1].opts.method, 'PUT');
  assert.equal(JSON.parse(capturedCalls[1].opts.body).state, 'inactive');
});

test('patchPrerequisites: no PATCH when clearing a list that was never stored', async () => {
  mockFetchSequence([{ body: kratosIdentity({ id: 'u7', traits: {}, metadata_admin: {} }) }]);
  await patchPrerequisites('u7', []);
  assert.equal(capturedCalls.length, 1);
});

test('patchPrerequisites: adds the key beside existing metadata', async () => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'u8', traits: {}, metadata_admin: { groups: ['family'] } }) },
    { body: kratosIdentity({ id: 'u8', traits: {} }) },
  ]);
  await patchPrerequisites('u8', ['tailscale']);
  assert.deepEqual(JSON.parse(capturedCalls[1].opts.body), [{ op: 'add', path: '/metadata_admin/prerequisites', value: ['tailscale'] }]);
});

test('a 404 means already gone for revokeSession, listSessions and deleteCredential', async () => {
  mockFetch({ error: { code: 404 } }, 404);
  await revokeSession('s1');
  assert.deepEqual(await listSessions('u9'), []);
  await deleteCredential('u9', 'webauthn');
  assert.equal(capturedCalls.length, 3);
});

test('createIdentity and updateIdentity refuse an invalid metadata_admin before any Kratos call', async () => {
  const input = { traits: { email: 'a@othala.test', username: 'ada' }, metadataAdmin: { groups: ['Bad Group'] } };
  for (const call of [() => createIdentity(input), () => updateIdentity('id-1', input)]) {
    mockFetch(kratosIdentity({ id: 'id-1', traits: {} }));
    await assert.rejects(call, MetadataAdminError);
    assert.equal(capturedCalls.length, 0);
  }
});

test('listIdentities: asks for one page of 250 and fetches no further page', async () => {
  mockFetch([kratosIdentity({ id: 'a', traits: {} })]);
  await listIdentities();
  assert.equal(capturedCalls.length, 1);
  assert.equal(new URL(capturedCalls[0].url).searchParams.get('per_page'), '250');
});

const PIC = avatarOf('png');
const savedMetadata = () => JSON.parse(capturedCalls[1].opts.body).metadata_admin;
const updateAgainst = async (stored, input = { groups: ['family'], roles: { wiki: 'viewer' } }) => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'u10', traits: {}, schema_id: 'family', metadata_admin: stored }) },
    { body: kratosIdentity({ id: 'u10', traits: {} }) },
  ]);
  await updateIdentity('u10', { traits: { username: 'robin' }, metadataAdmin: input });
  return savedMetadata();
};

test('updateIdentity carries admin, avatar, passkey names and prerequisites from the identity it reads, not the caller', async () => {
  const saved = await updateAgainst({
    groups: ['old'],
    roles: { old: 'x' },
    admin: true,
    avatar: PIC,
    passkeyNames: { 'abcd01': 'Laptop' },
    prerequisites: ['tailscale'],
  });
  assert.deepEqual(saved.groups, ['family']);
  assert.deepEqual(saved.roles, { wiki: 'viewer' });
  assert.equal(saved.admin, true);
  assert.deepEqual(saved.avatar, PIC);
  assert.deepEqual(saved.passkeyNames, { 'abcd01': 'Laptop' });
  assert.deepEqual(saved.prerequisites, ['tailscale']);
});

test('updateIdentity does not restore an admin marker that was revoked since the caller read the person', async () => {
  const saved = await updateAgainst({ groups: ['family'] });
  assert.ok(!('admin' in saved));
});

test('updateIdentity drops a malformed stored avatar and keeps the rest', async () => {
  const saved = await updateAgainst({ groups: ['family'], avatar: { ...PIC, type: 'image/svg+xml' }, passkeyNames: { 'abcd01': 'Laptop' } });
  assert.ok(!('avatar' in saved));
  assert.deepEqual(saved.passkeyNames, { 'abcd01': 'Laptop' });
});

test('updateIdentity leaves out empty carried keys', async () => {
  const saved = await updateAgainst({ groups: ['family'], admin: false, prerequisites: [], passkeyNames: {} }, { groups: ['family'] });
  assert.deepEqual(Object.keys(saved).sort(), ['groups']);
});
