/**
 * session.ts — Kratos session probe helpers.
 *
 * Probes GET /sessions/whoami on the Othala edge (which Caddy routes to
 * kratos:4433/sessions/whoami). The session cookie in the BrowserContext
 * is automatically carried by ctx.request.
 */

import type { BrowserContext } from '@playwright/test';

export interface WhoAmI {
  id: string;
  active: boolean;
  identity: {
    id: string;
    traits: {
      email?: string;
      username?: string;
      [key: string]: unknown;
    };
    metadata_admin?: {
      groups?: string[];
      [key: string]: unknown;
    };
    [key: string]: unknown;
  };
  authenticator_assurance_level?: string;
  [key: string]: unknown;
}

/**
 * hasSession — returns true iff the context's session cookie is accepted by
 * Kratos (i.e. /sessions/whoami responds 200 with active:true).
 */
export async function hasSession(ctx: BrowserContext, base: string): Promise<boolean> {
  try {
    const resp = await ctx.request.get(`${base}/sessions/whoami`, {
      headers: { Accept: 'application/json' },
    });
    if (!resp.ok()) return false;
    const body = await resp.json();
    return body?.active === true;
  } catch {
    return false;
  }
}

/**
 * getSession — fetch the full /sessions/whoami payload.
 * Returns null on 401 or network error.
 */
export async function getSession(ctx: BrowserContext, base: string): Promise<WhoAmI | null> {
  try {
    const resp = await ctx.request.get(`${base}/sessions/whoami`, {
      headers: { Accept: 'application/json' },
    });
    if (!resp.ok()) return null;
    return (await resp.json()) as WhoAmI;
  } catch {
    return null;
  }
}
