import { afterEach, describe, expect, it, vi } from 'vitest';
import { kratosAdmin, timeoutFetch } from './ory-fetch';

function hang(): typeof fetch {
  return (_input, init) =>
    new Promise((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(init.signal!.reason));
    });
}

describe('timeoutFetch', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('rejects a call that never settles once the timeout elapses', async () => {
    vi.stubGlobal('fetch', hang());
    await expect(timeoutFetch(20)('http://x')).rejects.toMatchObject({ name: 'TimeoutError' });
  });

  it('still honours a caller abort', async () => {
    vi.stubGlobal('fetch', hang());
    const ctl = new AbortController();
    const p = timeoutFetch(5_000)('http://x', { signal: ctl.signal });
    ctl.abort(new Error('caller'));
    await expect(p).rejects.toThrow('caller');
  });

  it('passes the response through', async () => {
    const res = new Response('ok');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(res));
    await expect(timeoutFetch()('http://x')).resolves.toBe(res);
  });
});

describe('kratosAdmin', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('gives up on a hung admin API after its ten-second budget', async () => {
    const realTimeout = AbortSignal.timeout.bind(AbortSignal);
    const budget = vi.spyOn(AbortSignal, 'timeout').mockImplementation((ms) => realTimeout(ms / 1000));
    vi.stubGlobal('fetch', hang());
    await expect(kratosAdmin().getIdentity({ id: 'x' })).rejects.toBeDefined();
    expect(budget).toHaveBeenCalledWith(10_000);
  });
});
