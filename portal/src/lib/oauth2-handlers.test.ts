import { describe, it, expect, vi } from 'vitest';
import { handleLogin } from './oauth2-handlers.js';

describe('handleLogin when Hydra is unreachable', () => {
  it('answers 502 and logs the failing step and error', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const oauth2 = { getOAuth2LoginRequest: vi.fn().mockRejectedValue(new Error('boom')) };
    const res = await handleLogin(new Request('http://portal.test/oauth2/login?login_challenge=c1'), {
      oauth2: oauth2 as never,
    });
    expect(res.status).toBe(502);
    expect(await res.text()).toBe('upstream error');
    expect(spy).toHaveBeenCalledWith('[portal] upstream failure', {
      step: 'getOAuth2LoginRequest',
      error: 'Error: boom',
    });
    spy.mockRestore();
  });
});
