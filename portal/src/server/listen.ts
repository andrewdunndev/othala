// Dual listener. PUBLIC (8080 on 0.0.0.0): the lazily imported Astro SSR handler (OAuth2 providers, /auth/*, /admin/*).
// ADMIN (4431 on PORTAL_ADMIN_BIND_HOST, default 127.0.0.1 outside production): its own mux for /healthz, /readyz and the six Kratos webhooks
// (recovery-gate, login-code-gate, profile-gate, second-factor-gate, profile-sessions, passkey-prune); never delegates to Astro.
// RECOVERY_GATE_SECRET guards the webhooks: constant-time compare, fail-closed when unset.
// Bundled by build:listener; run with `node ./dist/server/listen.mjs` after `npm run build`.
// Nothing imported statically may load lib/config.ts: it throws on the first missing production var, before
// startupEnvErrors can report them all. Env reads that config.ts also owns stay here for that reason.

import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { getIdentity, listSessions, revokeSession, prunePasskeyNames } from '../lib/admin-api';
import { decideAccess } from '../lib/gate';
import { secondFactorChangeVerdict, SECOND_FACTOR_UNAVAILABLE } from '../lib/second-factor-gate';
import { emailChangeVerdict, usernameChangeVerdict, PROFILE_UPDATE_UNAVAILABLE } from '../lib/profile-gate';
import { HYDRA_ADMIN_URL, KRATOS_ADMIN_URL, SECRET_MIN_BYTES } from '../lib/constants';
import type { Identity } from '../lib/types';
import { upstream } from '../lib/oauth2-handlers';

const PORT = 8080;
const HOST = '0.0.0.0';
const ADMIN_PORT = 4431; // Kratos webhooks in kratos.yml target this port
const isProd = () => process.env.NODE_ENV === 'production';
/** The admin bind address: required in production, loopback in dev and test. Read lazily so tests can set it. */
const adminBindHost = () => process.env.PORTAL_ADMIN_BIND_HOST ?? (isProd() ? '' : '127.0.0.1');

/** The Kratos admin client the hooks call; a parameter so tests can stand in a stub. */
const ADMIN_CLIENT = { getIdentity, listSessions, revokeSession, prunePasskeyNames };
type AdminClient = typeof ADMIN_CLIENT;
type Handler = (req: IncomingMessage, res: ServerResponse, client?: AdminClient) => unknown;
type Verdict = { refuse: boolean; admin?: boolean; reason: string };

function pathOf(url: string | undefined): string {
  return (url ?? '/').split('?')[0];
}

/** Constant-time bearer compare; an unset or empty secret rejects everything, even an empty token. */
export function bearerMatches(presented: unknown, expected: string): boolean {
  if (!expected) return false; // fail-closed: no secret configured
  if (typeof presented !== 'string' || presented.length === 0) return false;
  const a = Buffer.from(presented);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/** Extract a Bearer token from an Authorization header value. */
export function parseBearer(authHeader: unknown): string {
  if (typeof authHeader !== 'string') return '';
  const m = /^Bearer\s+(.+)$/.exec(authHeader.trim());
  return m ? m[1] : '';
}

/** Read a request body to a string (bounded). */
function readBody(req: IncomingMessage, limitBytes = 1_000_000): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > limitBytes) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendJson(res: ServerResponse, code: number, obj: unknown): void {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

/** Every webhook's auth: answer 403 and return true unless the request carries the RECOVERY_GATE_SECRET bearer. */
function refuseUnlessHookBearer(req: IncomingMessage, res: ServerResponse): boolean {
  if (bearerMatches(parseBearer(req.headers?.authorization), process.env.RECOVERY_GATE_SECRET ?? '')) return false;
  // 403, not 401: with can_interrupt a non-403 may be treated as a non-interrupting error (fail-open).
  sendJson(res, 403, { error: 'forbidden' });
  return true;
}

/**
 * Apply decideAccess's emailed-code rule to the identity read from the Kratos admin API (the payload carries only the id).
 * Fail-closed: any error returns `{ refuse: true, reason }`.
 */
export async function fetchAdminMarker(identityId: string, client: AdminClient = ADMIN_CLIENT): Promise<Verdict> {
  const fetched = await fetchStoredIdentity(client, identityId, 'recovery-gate');
  if (fetched.refuse) return fetched;
  if ('deny' in decideAccess(fetched.identity, 'emailed-code', null)) {
    return { refuse: true, admin: true, reason: 'admin recovery is console-only' };
  }
  return { refuse: false, reason: '' };
}

/** Fetch the stored identity via the Kratos admin client; fail-closed with `{ refuse: true, reason }` on a client error. */
async function fetchStoredIdentity(
  client: AdminClient,
  identityId: string,
  tag: string,
): Promise<{ refuse: false; identity: Identity } | { refuse: true; reason: string }> {
  try {
    return { refuse: false, identity: await client.getIdentity(identityId) };
  } catch (err) {
    console.error(`[portal/${tag}] admin API read failed for ${identityId}:`, (err as Error)?.message ?? err);
    return { refuse: true, reason: 'admin-api-unreachable (fail-closed)' };
  }
}

/** Login-by-code gate text: the first line for an admin marker, the second for any fail-closed path. */
export const LOGIN_CODE_ADMIN_REFUSAL = 'Admin accounts sign in with a passkey or password.';
export const LOGIN_CODE_UNAVAILABLE = 'Sign-in by code is unavailable right now. Use a passkey or password.';

export function loginCodeRefusalText(verdict: Partial<Verdict>): string {
  return verdict?.admin === true ? LOGIN_CODE_ADMIN_REFUSAL : LOGIN_CODE_UNAVAILABLE;
}

/**
 * POST /admin/recovery-gate. Bearer RECOVERY_GATE_SECRET; refuses recovery for admin identities, fail-closed on a
 * malformed payload or admin API error. Refusal is the Kratos-webhook error shape (403 + messages), allow is 200.
 */
export function handleRecoveryGate(req: IncomingMessage, res: ServerResponse, client?: AdminClient) {
  return handleAdminMarkerGate(req, res, client, (verdict) => `recovery refused: ${verdict.reason}`);
}

/** POST /admin/login-code-gate: recovery-gate's bearer, payload and lookup, wired to login.after.code; an admin-marked identity gets no session from an emailed code. */
export function handleLoginCodeGate(req: IncomingMessage, res: ServerResponse, client?: AdminClient) {
  return handleAdminMarkerGate(req, res, client, loginCodeRefusalText);
}

async function handleAdminMarkerGate(
  req: IncomingMessage,
  res: ServerResponse,
  client: AdminClient | undefined,
  refusalText: (verdict: Partial<Verdict>) => string,
): Promise<void> {
  if (refuseUnlessHookBearer(req, res)) return;
  let body;
  try {
    body = JSON.parse((await readBody(req)) || '{}');
  } catch {
    sendJson(res, 403, {
      messages: [{ messages: [{ type: 'error', text: refusalText({ reason: 'malformed payload' }) }] }],
    });
    return;
  }

  const id = body?.identity_id ?? body?.identity?.id;
  if (typeof id !== 'string' || id.trim().length === 0) {
    sendJson(res, 403, {
      messages: [{ messages: [{ type: 'error', text: refusalText({ reason: 'unidentifiable subject (fail-closed)' }) }] }],
    });
    return;
  }

  const adminVerdict = await fetchAdminMarker(id, client);
  if (adminVerdict.refuse) {
    sendJson(res, 403, {
      messages: [{ messages: [{ type: 'error', text: refusalText(adminVerdict) }] }],
    });
    return;
  }

  sendJson(res, 200, { ok: true });
}

function refuseProfile(res: ServerResponse, text: string, pointers = ['#/traits/username']): void {
  sendJson(res, 403, {
    messages: pointers.map((instance_ptr) => ({ instance_ptr, messages: [{ id: 4000001, type: 'error', text }] })),
  });
}

type HookBody = { identity_id?: unknown; traits?: Record<string, unknown> | null; authentication_methods?: unknown } | null;

/** A settings webhook's bearer, payload and stored-identity read; calls refuse() and returns null on any failure. */
async function hookIdentity(
  req: IncomingMessage,
  res: ServerResponse,
  client: AdminClient,
  tag: string,
  refuse: () => void,
): Promise<{ body: HookBody; identity: Identity } | null> {
  if (refuseUnlessHookBearer(req, res)) return null;
  let body: HookBody;
  try {
    body = JSON.parse((await readBody(req)) || '{}');
  } catch {
    refuse();
    return null;
  }
  const id = body?.identity_id;
  if (typeof id !== 'string' || id.trim().length === 0) {
    refuse();
    return null;
  }
  const fetched = await fetchStoredIdentity(client, id, tag);
  if (fetched.refuse) {
    refuse();
    return null;
  }
  return { body, identity: fetched.identity };
}

/** POST /admin/profile-gate, wired to settings.after.profile with can_interrupt; a failed identity read refuses the update. Username stays fixed; an email change needs a first-factor sign-in when the account has a key. */
export async function handleProfileGate(req: IncomingMessage, res: ServerResponse, client: AdminClient = ADMIN_CLIENT) {
  const hook = await hookIdentity(req, res, client, 'profile-gate', () => refuseProfile(res, PROFILE_UPDATE_UNAVAILABLE));
  if (!hook) return;
  const { body, identity } = hook;
  const verdict = usernameChangeVerdict(identity, body?.traits?.username);
  if (verdict.refuse) {
    refuseProfile(res, verdict.text);
    return;
  }
  const emailVerdict = emailChangeVerdict(identity, body?.traits, body?.authentication_methods);
  if (emailVerdict.refuse) {
    refuseProfile(res, emailVerdict.text, emailVerdict.pointers);
    return;
  }
  sendJson(res, 200, { ok: true });
}

/** POST /admin/second-factor-gate?method=totp|webauthn, wired to settings.after.{totp,webauthn} with can_interrupt; a failed read or missing id refuses the change. */
export async function handleSecondFactorGate(req: IncomingMessage, res: ServerResponse, client: AdminClient = ADMIN_CLIENT) {
  const hook = await hookIdentity(req, res, client, 'second-factor-gate', () => refuseProfile(res, SECOND_FACTOR_UNAVAILABLE, ['#/']));
  if (!hook) return;
  const method = new URLSearchParams((req.url ?? '').split('?')[1] ?? '').get('method') ?? '';
  const verdict = secondFactorChangeVerdict(hook.identity, method);
  if (verdict.refuse) {
    refuseProfile(res, verdict.text, ['#/']);
    return;
  }
  sendJson(res, 200, { ok: true });
}

/**
 * POST /admin/profile-sessions, wired to settings.after.profile without can_interrupt: ends every other session of
 * the identity. Failures are logged and still answered 200 (the change already saved); without `session_id`
 * nothing is ended.
 */
export async function handleProfileSessions(req: IncomingMessage, res: ServerResponse, client: AdminClient = ADMIN_CLIENT) {
  if (refuseUnlessHookBearer(req, res)) return;
  const tag = '[portal/profile-sessions]';
  let body;
  try {
    body = JSON.parse((await readBody(req)) || '{}');
  } catch {
    body = {};
  }
  const id = body?.identity_id;
  const keep = body?.session_id;
  if (typeof id !== 'string' || !id.trim() || typeof keep !== 'string' || !keep.trim()) {
    console.error(`${tag} identity_id or session_id missing; other sessions left active`);
    sendJson(res, 200, { ended: 0 });
    return;
  }
  let ended = 0;
  try {
    for (const s of await client.listSessions(id)) {
      if (typeof s?.id !== 'string' || s.id === keep) continue;
      try {
        await client.revokeSession(s.id);
        ended += 1;
      } catch (err) {
        console.error(`${tag} ending session for identity_id=${JSON.stringify(id)} failed:`, (err as Error)?.message ?? err);
      }
    }
  } catch (err) {
    console.error(`${tag} could not end other sessions for identity_id=${JSON.stringify(id)}:`, (err as Error)?.message ?? err);
  }
  sendJson(res, 200, { ended });
}

/**
 * POST /admin/passkey-prune, wired to settings.after.passkey (post-persist, not interrupting): drops passkey names whose
 * credential is gone. Bad auth is 403; every other failure is logged and still answered 200, the change already saved.
 */
export async function handlePasskeyPrune(req: IncomingMessage, res: ServerResponse, client: AdminClient = ADMIN_CLIENT) {
  if (refuseUnlessHookBearer(req, res)) return;
  const tag = '[portal/passkey-prune]';
  let id;
  try {
    id = JSON.parse((await readBody(req)) || '{}')?.identity_id;
  } catch {
    id = undefined;
  }
  if (typeof id !== 'string' || !id.trim()) {
    console.error(`${tag} identity_id missing; nothing pruned`);
    sendJson(res, 200, { pruned: 0 });
    return;
  }
  let pruned = 0;
  try {
    pruned = await client.prunePasskeyNames(id);
  } catch (err) {
    console.error(`${tag} could not prune names for identity_id=${JSON.stringify(id)}:`, (err as Error)?.message ?? err);
  }
  sendJson(res, 200, { pruned });
}

const READY_TIMEOUT_MS = 2000;

/** Readiness: Kratos and Hydra both answer ready within the timeout; 503 names the dependencies that do not. */
async function handleReadyz(res: ServerResponse): Promise<void> {
  const probes = {
    kratos: `${KRATOS_ADMIN_URL}/admin/health/ready`,
    hydra: `${HYDRA_ADMIN_URL}/health/ready`,
  };
  const failed: string[] = [];
  await Promise.all(
    Object.entries(probes).map(async ([name, url]) => {
      try {
        const r = await fetch(url, { signal: AbortSignal.timeout(READY_TIMEOUT_MS) });
        if (!r.ok) failed.push(name);
        await r.body?.cancel();
      } catch {
        failed.push(name);
      }
    }),
  );
  if (failed.length) sendJson(res, 503, { status: 'unavailable', failed: failed.sort() });
  else sendJson(res, 200, { status: 'ok' });
}

/** The admin mux, by method then path. Disjoint from the public routes. */
export const ADMIN_GET: ReadonlyMap<string, Handler> = new Map<string, Handler>([
  ['/healthz', (_req, res) => sendJson(res, 200, { status: 'ok' })],
  ['/readyz', (_req, res) => handleReadyz(res)],
]);
export const ADMIN_POST: ReadonlyMap<string, Handler> = new Map<string, Handler>([
  ['/admin/recovery-gate', handleRecoveryGate],
  ['/admin/login-code-gate', handleLoginCodeGate],
  ['/admin/profile-gate', handleProfileGate],
  ['/admin/second-factor-gate', handleSecondFactorGate],
  ['/admin/profile-sessions', handleProfileSessions],
  ['/admin/passkey-prune', handlePasskeyPrune],
]);

function adminHandler(method: string | undefined, url: string | undefined): Handler | undefined {
  if (method === 'GET') return ADMIN_GET.get(pathOf(url));
  if (method === 'POST') return ADMIN_POST.get(pathOf(url));
  return undefined;
}

/** Handle one admin-port request. Writes to res; never touches the SSR handler. */
export async function handleAdminRequest(req: IncomingMessage, res: ServerResponse, client?: AdminClient): Promise<void> {
  const handler = adminHandler(req.method, req.url);
  if (handler) {
    await handler(req, res, client);
    return;
  }
  // Everything else, including public paths and a served path on the wrong method, is 404 here.
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('not found');
}

/** Build the admin server (no socket bound until .listen). */
export function createAdminServer() {
  return http.createServer((req, res) => {
    handleAdminRequest(req, res).catch((err: unknown) => {
      upstream('admin-request', err);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('internal server error');
      }
    });
  });
}

/** Build the public server, lazily importing the built Astro SSR handler. */
export async function createPublicServer() {
  // Stop entry.mjs auto-binding its own server (ASTRO_NODE_AUTOSTART=disabled); this module drives `handler` itself.
  process.env.ASTRO_NODE_AUTOSTART = 'disabled';
  const { handler: ssrHandler } = await import('./entry.mjs');
  return http.createServer((req, res) => {
    ssrHandler(req, res, (err: unknown) => {
      // Unmatched route or error: emit a plain 404/500 rather than hang.
      if (err) {
        upstream('public-request', err);
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('internal server error');
        return;
      }
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('not found');
    });
  });
}

/**
 * Fail-closed startup checks (pure; test helper): a missing or short secret, or a wildcard PORTAL_ADMIN_BIND_HOST, each push a
 * FATAL message. In production PORTAL_ADMIN_BIND_HOST must be set; elsewhere it defaults to loopback.
 */
export function startupEnvErrors(): string[] {
  const errors: string[] = [];
  for (const name of ['RECOVERY_GATE_SECRET', 'CSRF_SECRET']) {
    const value = process.env[name] ?? '';
    if (!value.trim()) {
      errors.push(`[portal] FATAL: ${name} is not set or empty — refusing to start`);
    } else if (Buffer.byteLength(value, 'utf8') < SECRET_MIN_BYTES) {
      errors.push(`[portal] FATAL: ${name} is shorter than ${SECRET_MIN_BYTES} bytes (UTF-8) — refusing to start`);
    }
  }

  // Production only: config.ts throws on these at first import, this surfaces it at boot instead of on the first request.
  if (isProd()) {
    for (const name of ['OTHALA_PUBLIC_URL', 'OTHALA_APEX', 'OTHALA_INSTANCE_NAME', 'OTHALA_CONTACT_RECIPIENT', 'OTHALA_SMTP_CONNECTION_URI']) {
      if (!(process.env[name] ?? '').trim()) errors.push(`[portal] FATAL: ${name} is not set or empty — refusing to start`);
    }
  }

  const bind = adminBindHost();
  if (isProd() && !bind.trim()) {
    errors.push('[portal] FATAL: PORTAL_ADMIN_BIND_HOST is not set or empty — refusing to start');
  } else if (bind === '0.0.0.0' || bind === '::' || bind === '') {
    errors.push(`[portal] FATAL: PORTAL_ADMIN_BIND_HOST is a wildcard address (${JSON.stringify(bind)}) — the admin port must be bound to an internal-network address, never a wildcard (0.0.0.0, :: or empty)`);
  }

  return errors;
}

/** Fatal-exits if startupEnvErrors() finds anything. Called before binding any socket. */
function assertStartupEnv(): void {
  const errors = startupEnvErrors();
  if (errors.length > 0) {
    for (const msg of errors) console.error(msg);
    process.exit(1);
  }
}

// Bind both listeners only when run as the entrypoint (tests import the pure mux).
if (import.meta.url === `file://${process.argv[1]}`) {
  assertStartupEnv();

  const publicServer = await createPublicServer();
  publicServer.listen(PORT, HOST, () => {
    console.log(`[portal] public listener on http://${HOST}:${PORT}`);
  });

  const adminServer = createAdminServer();
  adminServer.listen(ADMIN_PORT, adminBindHost(), () => {
    console.log(`[portal] admin listener on http://${adminBindHost()}:${ADMIN_PORT}`);
  });

  // In-process OIDC client reconciler, started after both listeners are bound so a slow Hydra never delays boot.
  // Boot retries with backoff, then logs an operator notice and keeps serving; SIGHUP drops the manifest cache and
  // reconciles again. It stays its own bundle (build:registrar) because it loads config.ts.
  const registrar = await import('./registrar.mjs');
  registrar.reconcileOnBoot().catch((e: unknown) => console.error('[portal] boot reconcile error', e));
  process.on('SIGHUP', () => {
    registrar.reloadOnSighup().catch((e: unknown) => console.error('[portal] SIGHUP reload error', e));
  });
}
