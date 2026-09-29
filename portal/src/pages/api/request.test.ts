import { describe, it, expect, vi, beforeEach } from 'vitest';

const { getSessionMock, sendMock } = vi.hoisted(() => ({ getSessionMock: vi.fn(), sendMock: vi.fn() }));

vi.mock('../../lib/kratos', () => ({ getSession: getSessionMock }));
vi.mock('../../lib/mailer', () => ({
  sendContactRequest: sendMock,
  MailerError: class MailerError extends Error {},
}));
vi.mock('../../lib/config', () => ({ contactRecipient: 'ops@example.test' }));

import { POST } from './request.js';
import { _resetForTests } from '../../lib/contact.js';
import { identity, session, whoamiIdentity } from '../../lib/test-builders.js';

const BODY = { name: 'Robin', type: 'access', message: 'please grant access to an app' };

function call(cookie?: string, clientAddress = '203.0.113.9') {
  const request = new Request('http://portal.test/api/request', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(BODY),
  });
  return POST({ request, clientAddress } as never) as Promise<Response>;
}

beforeEach(() => {
  getSessionMock.mockReset();
  sendMock.mockReset();
  sendMock.mockResolvedValue(undefined);
  _resetForTests();
});

describe('POST /api/request', () => {
  it('answers 401 and sends nothing without a session', async () => {
    getSessionMock.mockResolvedValue(null);
    const r = await call();
    expect(r.status).toBe(401);
    expect(sendMock).not.toHaveBeenCalled();
  });

  it('sends with the verified identity id and username, forwarding the cookie', async () => {
    const who = identity({ id: '11111111-2222-3333-4444-555555555555', username: 'robin' });
    getSessionMock.mockResolvedValue(session('aal1', ['password'], { identity: whoamiIdentity(who) }));
    const r = await call('ory_kratos_session=abc');
    expect(r.status).toBe(200);
    expect(getSessionMock).toHaveBeenCalledWith('ory_kratos_session=abc');
    expect(sendMock).toHaveBeenCalledWith(
      expect.objectContaining({ identityId: who.id, username: 'robin', to: 'ops@example.test' }),
    );
  });

  it('limits per identity, not per address', async () => {
    const a = whoamiIdentity(identity({ id: 'aaaaaaaa-0000-0000-0000-000000000001', username: 'a' }));
    const b = whoamiIdentity(identity({ id: 'aaaaaaaa-0000-0000-0000-000000000002', username: 'b' }));
    getSessionMock.mockResolvedValue(session('aal1', ['password'], { identity: a }));
    let last = 200;
    for (let i = 0; i < 50 && last === 200; i++) last = (await call('c=1')).status;
    expect(last).toBe(429);
    getSessionMock.mockResolvedValue(session('aal1', ['password'], { identity: b }));
    expect((await call('c=2')).status).toBe(200);
  });

  it('answers 503 when the session lookup fails', async () => {
    getSessionMock.mockRejectedValue(new Error('down'));
    expect((await call('c=1')).status).toBe(503);
    expect(sendMock).not.toHaveBeenCalled();
  });
});
