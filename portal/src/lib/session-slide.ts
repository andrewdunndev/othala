import type { Session } from './types';
import { getSessionRelay } from './kratos';
import { kratosAdmin } from './ory-fetch';
import { POLICY_DIR } from './constants';
import { kratosDurationMs } from './contract';

// Counted from authenticated_at, which an extend never moves; an extend past it is skipped, so no Kratos cookie outlives a year since sign-in.
export const ABSOLUTE_CAP_MS = 365 * 86_400_000;

/** The idle window is kratos.yml session.lifespan, read from the shipped policy rather than kept as a second copy. */
export function idleMs(policyDir: string = POLICY_DIR): number {
  return kratosDurationMs(['session', 'lifespan'], policyDir);
}

export interface Slid {
  session: Session | null;
  setCookie: string[];
}

export interface SlideDeps {
  extend: (id: string) => Promise<unknown>;
  whoami: (cookie: string) => Promise<Slid | null>;
  idleMs: () => number;
}

const live: SlideDeps = {
  extend: (id) => kratosAdmin().extendSession({ id }),
  whoami: getSessionRelay,
  idleMs: () => idleMs(),
};

// Kratos extends by id without checking the row is active, so only a session whoami just reported active gets here.
export async function slide(
  session: Session | null,
  cookie: string | undefined,
  now: number = Date.now(),
  deps: SlideDeps = live,
): Promise<Slid> {
  const none = { session, setCookie: [] };
  if (!cookie || !session?.active || !session.identity) return none;
  const signedIn = new Date(session.authenticated_at ?? NaN).getTime();
  try {
    if (!(now + deps.idleMs() - signedIn <= ABSOLUTE_CAP_MS)) return none;
    await deps.extend(session.id);
    const fresh = await deps.whoami(cookie);
    // Kratos reissues the cookie in whoami's reply, and the server-side call has no browser to hand it to.
    return fresh?.session?.active ? fresh : none;
  } catch (err) {
    console.error('[portal] session slide failed', { error: String(err) });
    return none;
  }
}
