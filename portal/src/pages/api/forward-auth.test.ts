import { describe, it, expect, vi, beforeEach } from 'vitest';

const { getSessionMock, getIdentityMock, healthMock } = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  getIdentityMock: vi.fn(),
  healthMock: vi.fn(),
}));

vi.mock('../../lib/kratos', () => ({ getSession: getSessionMock }));
vi.mock('../../lib/admin-api', () => ({ getIdentity: getIdentityMock }));
vi.mock('../../lib/manifest-store', () => ({ servingManifests: () => [], manifestHealth: healthMock }));

import { GET } from './forward-auth.js';
import { identity, session } from '../../lib/test-builders.js';

function call(group: string) {
  const url = new URL(`http://portal.test/api/forward-auth?group=${group}`);
  return GET({ request: new Request(url, { headers: { cookie: 'c=1' } }), url } as never) as Promise<Response>;
}

beforeEach(() => {
  getIdentityMock.mockResolvedValue(identity({ metadataAdmin: { groups: ['grafana-admin'] } }));
  healthMock.mockReturnValue({ status: 'unavailable', error: 'x', failingSinceMs: 0, serving: 0 });
});

describe('GET /api/forward-auth with no manifest set', () => {
  it('answers 503 to an aal1 session, since the role rule cannot be evaluated', async () => {
    getSessionMock.mockResolvedValue(session('aal1'));
    expect((await call('grafana-admin')).status).toBe(503);
  });

  it('allows an aal2 session in the group', async () => {
    getSessionMock.mockResolvedValue(session('aal2', ['password', 'totp']));
    expect((await call('grafana-admin')).status).toBe(200);
  });
});
