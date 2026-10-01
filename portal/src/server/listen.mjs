// Dual listener. PUBLIC (8080 on 0.0.0.0): the lazily imported Astro SSR handler (OAuth2 providers, /auth/*, /admin/*).
// ADMIN (4431 on PORTAL_ADMIN_BIND_HOST, default 127.0.0.1 outside production): its own mux for /healthz, /readyz and the five Kratos webhooks
// (recovery-gate, login-code-gate, profile-gate, second-factor-gate, profile-sessions); never delegates to Astro.
// RECOVERY_GATE_SECRET guards the webhooks: constant-time compare, fail-closed when unset.
// Run with `node ./dist/server/listen.mjs` after `npm run build`.

import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';

const PORT = 8080;
const HOST = '0.0.0.0';
const ADMIN_PORT = 4431; // Kratos webhooks in kratos.yml target this port
const isProd = () => process.env.NODE_ENV === 'production';
/** The admin bind address: required in production, loopback in dev and test. Read lazily so tests can set it. */
const adminBindHost = () => process.env.PORTAL_ADMIN_BIND_HOST ?? (isProd() ? '' : '127.0.0.1');

/** GET routes the admin mux serves. Disjoint from the public routes. */
export const ADMIN_GET_ROUTES = new Set(['/healthz', '/readyz']);
/** POST routes the admin mux serves. Disjoint from the public routes. */
export const ADMIN_POST_ROUTES = new Set([
  '/admin/recovery-gate',
  '/admin/login-code-gate',
  '/admin/profile-gate',
  '/admin/second-factor-gate',
  '/admin/profile-sessions',
]);

function pathOf(url) {
  return (url ?? '/').split('?')[0];
}

/** Report whether a request is an admin GET route (pure; test helper). */
export function isAdminRoute(method, url) {
  return method === 'GET' && ADMIN_GET_ROUTES.has(pathOf(url));
}

/** Report whether a request is any served admin route (GET or POST). */
export function isAdminEndpoint(method, url) {
  const path = pathOf(url);
  if (method === 'GET') return ADMIN_GET_ROUTES.has(path);
  if (method === 'POST') return ADMIN_POST_ROUTES.has(path);
  return false;
}

/** Constant-time bearer compare; an unset or empty secret rejects everything, even an empty token. */
export function bearerMatches(presented, expected) {
  if (!expected) return false; // fail-closed: no secret configured
  if (typeof presented !== 'string' || presented.length === 0) return false;
  const a = Buffer.from(presented);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/** Extract a Bearer token from an Authorization header value. */
export function parseBearer(authHeader) {
  if (typeof authHeader !== 'string') return '';
  const m = /^Bearer\s+(.+)$/.exec(authHeader.trim());
  return m ? m[1] : '';
}

/** Read a request body to a string (bounded). */
function readBody(req, limitBytes = 1_000_000) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
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

function sendJson(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

/** Lazily load dist/server/admin-runtime.mjs (Kratos admin client, second-factor verdict); cached, injectable in tests. */
let _runtime = null;
async function loadRuntime() {
  if (_runtime) return _runtime;
  _runtime = await import('./admin-runtime.mjs');
  return _runtime;
}

/**
 * Read an identity's admin marker from the Kratos admin API (the hook payload carries only the id).
 * Fail-closed: any error returns `{ refuse: true, reason }`.
 * @param {string} identityId Kratos identity UUID from the webhook payload.
 * @param {object} [runtime] injectable; defaults to the built bundle.
 * @returns {{ refuse: boolean, reason: string }}
 */
export async function fetchAdminMarker(identityId, runtime) {
  const fetched = await fetchStoredIdentity(runtime, identityId, 'recovery-gate');
  if (fetched.refuse) return fetched;
  if (fetched.rt.isAdminMarker(fetched.identity)) {
    return { refuse: true, admin: true, reason: 'admin recovery is console-only' };
  }
  return { refuse: false, reason: '' };
}

/** Fetch the stored identity via the runtime's Kratos admin client; fail-closed with `{ refuse: true, reason }` on an unloadable runtime or client error. */
async function fetchStoredIdentity(runtime, identityId, tag) {
  try {
    const rt = runtime ?? (await loadRuntime());
    return { refuse: false, identity: await rt.getIdentity(identityId), rt };
  } catch (err) {
    console.error(`[portal/${tag}] admin API read failed for ${identityId}:`, err?.message ?? err);
    return { refuse: true, reason: 'admin-api-unreachable (fail-closed)' };
  }
}

/** Login-by-code gate text: the first line for an admin marker, the second for any fail-closed path. */
export const LOGIN_CODE_ADMIN_REFUSAL = 'Admin accounts sign in with a passkey or password.';
export const LOGIN_CODE_UNAVAILABLE = 'Sign-in by code is unavailable right now. Use a passkey or password.';

export function loginCodeRefusalText(verdict) {
  return verdict?.admin === true ? LOGIN_CODE_ADMIN_REFUSAL : LOGIN_CODE_UNAVAILABLE;
}

/**
 * POST /admin/recovery-gate. Bearer RECOVERY_GATE_SECRET; refuses recovery for admin identities, fail-closed on a
 * malformed payload or admin API error. Refusal is the Kratos-webhook error shape (403 + messages), allow is 200.
 */
export function handleRecoveryGate(req, res, runtime) {
  return handleAdminMarkerGate(req, res, runtime, (verdict) => `recovery refused: ${verdict.reason}`);
}

/** POST /admin/login-code-gate: recovery-gate's bearer, payload and lookup, wired to login.after.code; an admin-marked identity gets no session from an emailed code. */
export function handleLoginCodeGate(req, res, runtime) {
  return handleAdminMarkerGate(req, res, runtime, loginCodeRefusalText);
}

async function handleAdminMarkerGate(req, res, runtime, refusalText) {
  const expected = process.env.RECOVERY_GATE_SECRET ?? '';
  if (!bearerMatches(parseBearer(req.headers?.authorization), expected)) {
    // 403, not 401: with can_interrupt a non-403 may be treated as a non-interrupting error (fail-open).
    sendJson(res, 403, { error: 'forbidden' });
    return;
  }
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

  const adminVerdict = await fetchAdminMarker(id, runtime);
  if (adminVerdict.refuse) {
    sendJson(res, 403, {
      messages: [{ messages: [{ type: 'error', text: refusalText(adminVerdict) }] }],
    });
    return;
  }

  sendJson(res, 200, { ok: true });
}

/** Username gate text: the username keys some apps' accounts, so only an administrator changes it. */
export const USERNAME_CHANGE_REFUSAL = 'Your username can only be changed by an administrator.';
export const PROFILE_UPDATE_UNAVAILABLE = 'Profile changes are unavailable right now. Try again later.';

/** Username-gate verdict (pure): refuse unless `stored` (pre-save) and `proposed` are the same non-empty string. */
export function usernameChangeVerdict(stored, proposed) {
  const current = stored?.traits?.username;
  if (typeof current !== 'string' || current.length === 0 || typeof proposed !== 'string') {
    return { refuse: true, text: PROFILE_UPDATE_UNAVAILABLE };
  }
  if (proposed !== current) return { refuse: true, text: USERNAME_CHANGE_REFUSAL };
  return { refuse: false };
}

function refuseProfile(res, text, pointers = ['#/traits/username']) {
  sendJson(res, 403, {
    messages: pointers.map((instance_ptr) => ({ instance_ptr, messages: [{ id: 4000001, type: 'error', text }] })),
  });
}

/** POST /admin/profile-gate, wired to settings.after.profile with can_interrupt; a failed identity read refuses the update. Username stays fixed; an email change needs a first-factor sign-in when the account has a key. */
export async function handleProfileGate(req, res, runtime) {
  const expected = process.env.RECOVERY_GATE_SECRET ?? '';
  if (!bearerMatches(parseBearer(req.headers?.authorization), expected)) {
    sendJson(res, 403, { error: 'forbidden' });
    return;
  }
  let body;
  try {
    body = JSON.parse((await readBody(req)) || '{}');
  } catch {
    refuseProfile(res, PROFILE_UPDATE_UNAVAILABLE);
    return;
  }
  const id = body?.identity_id;
  if (typeof id !== 'string' || id.trim().length === 0) {
    refuseProfile(res, PROFILE_UPDATE_UNAVAILABLE);
    return;
  }
  const fetched = await fetchStoredIdentity(runtime, id, 'profile-gate');
  if (fetched.refuse) {
    refuseProfile(res, PROFILE_UPDATE_UNAVAILABLE);
    return;
  }
  const verdict = usernameChangeVerdict(fetched.identity, body?.traits?.username);
  if (verdict.refuse) {
    refuseProfile(res, verdict.text);
    return;
  }
  const emailVerdict =
    typeof fetched.rt.emailChangeVerdict === 'function'
      ? fetched.rt.emailChangeVerdict(fetched.identity, body?.traits, body?.authentication_methods)
      : { refuse: true, text: PROFILE_UPDATE_UNAVAILABLE, pointers: ['#/traits/email'] };
  if (emailVerdict.refuse) {
    refuseProfile(res, emailVerdict.text, emailVerdict.pointers);
    return;
  }
  sendJson(res, 200, { ok: true });
}

function refuseSecondFactor(res, text) {
  sendJson(res, 403, { messages: [{ instance_ptr: '#/', messages: [{ id: 4000001, type: 'error', text }] }] });
}

/** POST /admin/second-factor-gate?method=totp|webauthn, wired to settings.after.{totp,webauthn} with can_interrupt; a failed read, missing id or unloadable runtime refuses the change. */
export async function handleSecondFactorGate(req, res, runtime) {
  const expected = process.env.RECOVERY_GATE_SECRET ?? '';
  if (!bearerMatches(parseBearer(req.headers?.authorization), expected)) {
    sendJson(res, 403, { error: 'forbidden' });
    return;
  }
  let rt;
  try {
    rt = runtime ?? (await loadRuntime());
  } catch (err) {
    console.error('[portal/second-factor-gate] runtime bundle failed to load:', err?.message ?? err);
  }
  const unavailable = rt?.SECOND_FACTOR_UNAVAILABLE ?? 'This change is unavailable right now. Try again later.';
  if (typeof rt?.secondFactorChangeVerdict !== 'function') {
    refuseSecondFactor(res, unavailable);
    return;
  }
  let body;
  try {
    body = JSON.parse((await readBody(req)) || '{}');
  } catch {
    refuseSecondFactor(res, unavailable);
    return;
  }
  const id = body?.identity_id;
  if (typeof id !== 'string' || id.trim().length === 0) {
    refuseSecondFactor(res, unavailable);
    return;
  }
  const method = new URLSearchParams((req.url ?? '').split('?')[1] ?? '').get('method') ?? '';
  const fetched = await fetchStoredIdentity(rt, id, 'second-factor-gate');
  const verdict = fetched.refuse
    ? { refuse: true, text: unavailable }
    : rt.secondFactorChangeVerdict(fetched.identity, method);
  if (verdict.refuse) {
    refuseSecondFactor(res, verdict.text);
    return;
  }
  sendJson(res, 200, { ok: true });
}

/**
 * POST /admin/profile-sessions, wired to settings.after.profile without can_interrupt: ends every other session of
 * the identity. Failures are logged and still answered 200 (the change already saved); without `session_id`
 * nothing is ended.
 */
export async function handleProfileSessions(req, res, runtime) {
  const expected = process.env.RECOVERY_GATE_SECRET ?? '';
  if (!bearerMatches(parseBearer(req.headers?.authorization), expected)) {
    sendJson(res, 403, { error: 'forbidden' });
    return;
  }
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
    const rt = runtime ?? (await loadRuntime());
    for (const s of await rt.listSessions(id)) {
      if (typeof s?.id !== 'string' || s.id === keep) continue;
      try {
        await rt.revokeSession(s.id);
        ended += 1;
      } catch (err) {
        console.error(`${tag} ending session for identity_id=${JSON.stringify(id)} failed:`, err?.message ?? err);
      }
    }
  } catch (err) {
    console.error(`${tag} could not end other sessions for identity_id=${JSON.stringify(id)}:`, err?.message ?? err);
  }
  sendJson(res, 200, { ended });
}

/** Handle one admin-port request. Writes to res; never touches the SSR handler. */
export async function handleAdminRequest(req, res, runtime) {
  const method = req.method;
  const path = pathOf(req.url);

  if (method === 'GET' && ADMIN_GET_ROUTES.has(path)) {
    sendJson(res, 200, { status: 'ok' });
    return;
  }
  if (method === 'POST' && path === '/admin/recovery-gate') {
    await handleRecoveryGate(req, res, runtime);
    return;
  }
  if (method === 'POST' && path === '/admin/login-code-gate') {
    await handleLoginCodeGate(req, res, runtime);
    return;
  }
  if (method === 'POST' && path === '/admin/profile-gate') {
    await handleProfileGate(req, res, runtime);
    return;
  }
  if (method === 'POST' && path === '/admin/second-factor-gate') {
    await handleSecondFactorGate(req, res, runtime);
    return;
  }
  if (method === 'POST' && path === '/admin/profile-sessions') {
    await handleProfileSessions(req, res, runtime);
    return;
  }

  // Everything else, including public paths and a served path on the wrong method, is 404 here.
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('not found');
}

/** Build the admin server (no socket bound until .listen). */
export function createAdminServer() {
  return http.createServer((req, res) => {
    handleAdminRequest(req, res).catch(() => {
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
    ssrHandler(req, res, (err) => {
      // Unmatched route or error: emit a plain 404/500 rather than hang.
      if (err) {
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
export function startupEnvErrors() {
  const errors = [];
  // 32-byte UTF-8 floor on both secrets, duplicated from csrf.ts (CRYPTO-2) because this .mjs cannot import TS.
  const recoverySecret = process.env.RECOVERY_GATE_SECRET ?? '';
  if (!recoverySecret.trim()) {
    errors.push('[portal] FATAL: RECOVERY_GATE_SECRET is not set or empty — refusing to start');
  } else if (Buffer.byteLength(recoverySecret, 'utf8') < 32) {
    errors.push('[portal] FATAL: RECOVERY_GATE_SECRET is shorter than 32 bytes (UTF-8) — refusing to start');
  }

  const csrfSecret = process.env.CSRF_SECRET ?? '';
  if (!csrfSecret.trim()) {
    errors.push('[portal] FATAL: CSRF_SECRET is not set or empty — refusing to start');
  } else if (Buffer.byteLength(csrfSecret, 'utf8') < 32) {
    errors.push('[portal] FATAL: CSRF_SECRET is shorter than 32 bytes (UTF-8) — refusing to start');
  }

  // Production only: config.ts throws on these at first import, this surfaces it at boot instead of on the first request.
  if (isProd()) {
    for (const name of ['OTHALA_PUBLIC_URL', 'OTHALA_APEX', 'OTHALA_INSTANCE_NAME']) {
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
function assertStartupEnv() {
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
  // reconciles again.
  const registrar = await import('./registrar.mjs');
  registrar.reconcileOnBoot().catch((e) => console.error('[portal] boot reconcile error', e));
  process.on('SIGHUP', () => {
    registrar.reloadOnSighup().catch((e) => console.error('[portal] SIGHUP reload error', e));
  });
}
