// Invariant: only a live session inside the 365-day cap is extended, and only the landing and /oauth2/login do it.

import { test, expect, vi } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { slide, ABSOLUTE_CAP_MS } from '../src/lib/session-slide.ts';
import { session, whoamiIdentity, identity } from '../src/lib/test-builders.ts';

const NOW = Date.UTC(2026, 10, 22);
const COOKIE = 'ory_kratos_session=abc';
const live = (over = {}) => session('aal1', ['passkey'], { identity: whoamiIdentity(identity({ id: 'id-1' })), ...over });

function deps(fresh) {
  return {
    extend: vi.fn(async () => ({})),
    whoami: vi.fn(async () => fresh ?? { session: live({ expires_at: new Date(NOW + 90 * 86_400_000) }), setCookie: ['ory_kratos_session=new; Max-Age=7776000'] }),
  };
}

// Pins: the extend call and the cookie relay (removing either leaves the old Max-Age or the old row).
test('an active session is extended by id and the reissued cookie is returned', async () => {
  const d = deps();
  const s = live({ authenticated_at: new Date(NOW - 10 * 86_400_000) });
  const out = await slide(s, COOKIE, NOW, d);
  expect(d.extend).toHaveBeenCalledWith(s.id);
  expect(d.whoami).toHaveBeenCalledWith(COOKIE);
  expect(out.setCookie).toEqual(['ory_kratos_session=new; Max-Age=7776000']);
  expect(out.session.expires_at.getTime()).toBe(NOW + 90 * 86_400_000);
});

// Pins: the active guard (Kratos would revive an expired row) and the no-cookie guard.
test.each([
  ['no session', null, COOKIE],
  ['an inactive session', live({ active: false }), COOKIE],
  ['no cookie', live(), undefined],
])('%s makes no call', async (_n, s, cookie) => {
  const d = deps();
  const out = await slide(s, cookie, NOW, d);
  expect(d.extend).not.toHaveBeenCalled();
  expect(d.whoami).not.toHaveBeenCalled();
  expect(out.setCookie).toEqual([]);
  expect(out.session).toBe(s);
});

// Pins: the absolute cap, in both directions, so neither a dropped guard nor an off-by-a-year bound passes.
test('an extend whose new expiry would pass the cap is skipped; one landing exactly on it is made', async () => {
  const IDLE = 90 * 86_400_000;
  const over = deps();
  await slide(live({ authenticated_at: new Date(NOW + IDLE - ABSOLUTE_CAP_MS - 1) }), COOKIE, NOW, over);
  expect(over.extend).not.toHaveBeenCalled();
  const inside = deps();
  await slide(live({ authenticated_at: new Date(NOW + IDLE - ABSOLUTE_CAP_MS) }), COOKIE, NOW, inside);
  expect(inside.extend).toHaveBeenCalledTimes(1);
});

// Pins: the fail-closed cap, since an unreadable authenticated_at must not read as "recent".
test('a session with no authenticated_at is not extended', async () => {
  const d = deps();
  await slide(live({ authenticated_at: undefined }), COOKIE, NOW, d);
  expect(d.extend).not.toHaveBeenCalled();
});

// Pins: the soft failure, so a Kratos hiccup never turns a sign-in into an error.
test('an extend error returns the original session and no cookie', async () => {
  const d = deps();
  d.extend.mockRejectedValue(new Error('kratos down'));
  const s = live();
  const out = await slide(s, COOKIE, NOW, d);
  expect(out).toEqual({ session: s, setCookie: [] });
});

// Pins: whoami must confirm the session is still active, or a revoked one would be relayed a fresh cookie.
test('a whoami that no longer reports the session active keeps the original and no cookie', async () => {
  const s = live();
  const out = await slide(s, COOKIE, NOW, deps({ session: live({ active: false }), setCookie: ['x=1'] }));
  expect(out).toEqual({ session: s, setCookie: [] });
});

// Pins: forward-auth never extends (Caddy drops the reply's Set-Cookie, so an extend there moves only the DB row).
test('only the landing and the OAuth login import the slide', () => {
  const root = join(import.meta.dirname, '../src');
  const users = [];
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(ts|astro)$/.test(e.name) && !/\.test\./.test(e.name) && readFileSync(p, 'utf8').includes('session-slide')) users.push(p.slice(root.length + 1));
    }
  };
  walk(root);
  expect(users.sort()).toEqual(['lib/oauth2-handlers.ts', 'lib/session-slide.ts', 'pages/index.astro']);
});
