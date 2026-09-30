// Dual-listener (D-listener) — CU1 item 4, extended in CU3, CVP-P3.
//
// Two in-process HTTP listeners, bound separately:
//
//   PUBLIC port (PORT, default 4321, bound on HOST default 0.0.0.0)
//     Serves the Astro SSR `handler` (the @astrojs/node middleware-mode
//     handler): the OAuth2 challenge providers (/oauth2/{login,consent,
//     logout}) AND the family UI + /auth/* + /admin/* pages. This is the
//     only handler exposed to the network. The SSR entry is imported LAZILY
//     so this module's pure admin mux can be unit-tested without a prior
//     `astro build`.
//
//   ADMIN port (ADMIN_PORT, default 4431, bound on ADMIN_HOST default
//     127.0.0.1 — loopback / pod-only)
//     A SEPARATE http.createServer with its own tiny mux. It serves:
//       GET  /healthz, /readyz        — liveness/readiness probes
//       POST /admin/recovery-gate     — Kratos recovery-gate webhook (CU3)
//       POST /admin/login-code-gate   — Kratos login-by-code webhook
//       POST /admin/username-gate     — Kratos profile-settings webhook
//       POST /admin/second-factor-gate — Kratos totp/webauthn-settings webhook
//       POST /admin/profile-sessions  — Kratos profile-settings post-save webhook
//     It NEVER delegates to the Astro `handler`, so no public route and no
//     challenge provider is reachable on the admin port — and the public
//     handler never sees admin paths. The two muxes are disjoint.
//
//   Secret model: RECOVERY_GATE_SECRET guards the five Kratos webhooks
//   above. The check is CONSTANT-TIME (timingSafeEqual) and FAIL-CLOSED (an
//   unset secret rejects every request).
//
// Run with:  node ./dist/server/listen.mjs   (after `npm run build`, which
// copies this file AND bundles dist/server/admin-runtime.mjs next to the
// built dist/server/entry.mjs).

import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';

const PORT = Number(process.env.PORT ?? 4321);
const HOST = process.env.HOST ?? '0.0.0.0';
const ADMIN_PORT = Number(process.env.ADMIN_PORT ?? 4431);
const ADMIN_HOST = process.env.ADMIN_HOST ?? '127.0.0.1';

/** GET routes the admin mux serves. Disjoint from the public routes. */
export const ADMIN_GET_ROUTES = new Set(['/healthz', '/readyz']);
/** POST routes the admin mux serves. Disjoint from the public routes. */
export const ADMIN_POST_ROUTES = new Set([
  '/admin/recovery-gate',
  '/admin/login-code-gate',
  '/admin/username-gate',
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

/**
 * Constant-time bearer comparison. FAIL-CLOSED: an unset/empty expected
 * secret rejects every request (returns false) even against an empty
 * presented token, so a misconfigured deployment never accidentally
 * authorizes. Length-mismatch is rejected without a content compare, but
 * the present-vs-expected compare itself is timing-safe.
 */
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

/**
 * Lazily load the runtime bundle (the Kratos admin client and the
 * second-factor verdict), compiled from src/server/admin-runtime.ts to
 * dist/server/admin-runtime.mjs by the build.
 * Cached after first import. Injected in tests so the admin handlers can be
 * exercised without the bundle.
 */
let _runtime = null;
async function loadRuntime() {
  if (_runtime) return _runtime;
  _runtime = await import('./admin-runtime.mjs');
  return _runtime;
}

/**
 * Look up an identity's admin marker directly from the Kratos admin API.
 *
 * The hook payload carries only the identity id; the authoritative admin marker
 * is fetched from the admin API.
 *
 * Fail-closed: any error (network, 4xx, malformed body) returns
 * `{ refuse: true, reason }` so a degraded admin API conservatively blocks
 * recovery rather than silently allowing it.
 *
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

/**
 * Fetch the stored identity through the runtime's Kratos admin client.
 * Fail-closed: an unset KRATOS_ADMIN_URL, an unloadable runtime or any client
 * error returns `{ refuse: true, reason }`; success returns `{ refuse: false, identity, rt }`.
 */
async function fetchStoredIdentity(runtime, identityId, tag) {
  if (!process.env.KRATOS_ADMIN_URL) {
    console.error(`[portal/${tag}] KRATOS_ADMIN_URL unset — cannot read the stored identity; refusing (fail-closed)`);
    return { refuse: true, reason: 'admin-api-unavailable (fail-closed)' };
  }
  try {
    const rt = runtime ?? (await loadRuntime());
    return { refuse: false, identity: await rt.getIdentity(identityId), rt };
  } catch (err) {
    console.error(`[portal/${tag}] admin API read failed for ${identityId}:`, err?.message ?? err);
    return { refuse: true, reason: 'admin-api-unreachable (fail-closed)' };
  }
}

/**
 * The login-by-code gate's user-facing text. An admin marker refuses with the
 * first line; any fail-closed path (no id, admin API unreachable) the second.
 */
export const LOGIN_CODE_ADMIN_REFUSAL = 'Admin accounts sign in with a passkey or password.';
export const LOGIN_CODE_UNAVAILABLE = 'Sign-in by code is unavailable right now. Use a passkey or password.';

export function loginCodeRefusalText(verdict) {
  return verdict?.admin === true ? LOGIN_CODE_ADMIN_REFUSAL : LOGIN_CODE_UNAVAILABLE;
}

/**
 * Handle POST /admin/recovery-gate. Bearer: RECOVERY_GATE_SECRET (constant-
 * time, fail-closed). Refuses recovery for admin identities; fail-closed on a
 * malformed payload or admin API error. Returns the Kratos-webhook error shape
 * on refusal (HTTP 403 + messages), 200 on allow.
 *
 * Admin authority is verified by fetching the identity from the Kratos admin
 * API (KRATOS_ADMIN_URL/admin/identities/:id) and reading metadata_admin.admin.
 */
export function handleRecoveryGate(req, res, runtime) {
  return handleAdminMarkerGate(req, res, runtime, (verdict) => `recovery refused: ${verdict.reason}`);
}

/**
 * Handle POST /admin/login-code-gate: the same bearer, payload and admin-API
 * lookup as the recovery gate, wired to selfservice.flows.login.after.code.
 * An admin-marked identity is refused a session from an emailed code.
 */
export function handleLoginCodeGate(req, res, runtime) {
  return handleAdminMarkerGate(req, res, runtime, loginCodeRefusalText);
}

async function handleAdminMarkerGate(req, res, runtime, refusalText) {
  const expected = process.env.RECOVERY_GATE_SECRET ?? '';
  if (!bearerMatches(parseBearer(req.headers?.authorization), expected)) {
    // 403 not 401: Kratos webhooks use can_interrupt: true; a non-403 response
    // (e.g. 401) risks being treated as a non-interrupting webhook error
    // (skip-and-continue = fail-open), whereas 403 reliably aborts the flow.
    sendJson(res, 403, { error: 'forbidden' });
    return;
  }
  let body;
  try {
    body = JSON.parse((await readBody(req)) || '{}');
  } catch {
    // Fail-closed: an unparseable webhook body refuses recovery.
    sendJson(res, 403, {
      messages: [{ messages: [{ type: 'error', text: refusalText({ reason: 'malformed payload' }) }] }],
    });
    return;
  }

  // Phase 1: fail-closed structural check (identity_id must be present).
  const id = body?.identity_id ?? body?.identity?.id;
  if (typeof id !== 'string' || id.trim().length === 0) {
    sendJson(res, 403, {
      messages: [{ messages: [{ type: 'error', text: refusalText({ reason: 'unidentifiable subject (fail-closed)' }) }] }],
    });
    return;
  }

  // Phase 2: fetch the authoritative admin marker from the Kratos admin API.
  const adminVerdict = await fetchAdminMarker(id, runtime);
  if (adminVerdict.refuse) {
    sendJson(res, 403, {
      messages: [{ messages: [{ type: 'error', text: refusalText(adminVerdict) }] }],
    });
    return;
  }

  sendJson(res, 200, { ok: true });
}

/**
 * The username gate's user-facing text. The username is the key some apps
 * match an account on at sign-in, so only an administrator changes it.
 */
export const USERNAME_CHANGE_REFUSAL = 'Your username can only be changed by an administrator.';
export const PROFILE_UPDATE_UNAVAILABLE = 'Profile changes are unavailable right now. Try again later.';

/**
 * Decide the username-gate verdict (pure). `stored` is the identity as the
 * admin API returns it (the value before this settings submission is
 * persisted); `proposed` is the username in the submitted traits. Anything but
 * an exact match of two non-empty strings refuses.
 */
export function usernameChangeVerdict(stored, proposed) {
  const current = stored?.traits?.username;
  if (typeof current !== 'string' || current.length === 0 || typeof proposed !== 'string') {
    return { refuse: true, text: PROFILE_UPDATE_UNAVAILABLE };
  }
  if (proposed !== current) return { refuse: true, text: USERNAME_CHANGE_REFUSAL };
  return { refuse: false };
}

function refuseUsername(res, text) {
  sendJson(res, 403, {
    messages: [{ instance_ptr: '#/traits/username', messages: [{ id: 4000001, type: 'error', text }] }],
  });
}

/**
 * Handle POST /admin/username-gate, wired to
 * selfservice.flows.settings.after.profile with can_interrupt, which Kratos
 * runs before it persists the new traits. Same bearer and body as the other
 * gates; the stored username is read from the admin API, so a failed read
 * refuses the whole profile update.
 */
export async function handleUsernameGate(req, res, runtime) {
  const expected = process.env.RECOVERY_GATE_SECRET ?? '';
  if (!bearerMatches(parseBearer(req.headers?.authorization), expected)) {
    sendJson(res, 403, { error: 'forbidden' });
    return;
  }
  let body;
  try {
    body = JSON.parse((await readBody(req)) || '{}');
  } catch {
    refuseUsername(res, PROFILE_UPDATE_UNAVAILABLE);
    return;
  }
  const id = body?.identity_id;
  if (typeof id !== 'string' || id.trim().length === 0) {
    refuseUsername(res, PROFILE_UPDATE_UNAVAILABLE);
    return;
  }
  const fetched = await fetchStoredIdentity(runtime, id, 'username-gate');
  const verdict = fetched.refuse
    ? { refuse: true, text: PROFILE_UPDATE_UNAVAILABLE }
    : usernameChangeVerdict(fetched.identity, body?.traits?.username);
  if (verdict.refuse) {
    refuseUsername(res, verdict.text);
    return;
  }
  sendJson(res, 200, { ok: true });
}

function refuseSecondFactor(res, text) {
  sendJson(res, 403, { messages: [{ instance_ptr: '#/', messages: [{ id: 4000001, type: 'error', text }] }] });
}

/**
 * Handle POST /admin/second-factor-gate?method=totp|webauthn, wired to
 * selfservice.flows.settings.after.{totp,webauthn} with can_interrupt, which
 * Kratos runs before it persists the change. Same bearer and body as the
 * other gates. The stored identity is read with its totp and webauthn configs
 * and judged by secondFactorChangeVerdict (lib/second-factor-gate.ts, via the
 * runtime bundle); a failed read, a missing id or a runtime that will not
 * load refuses the change.
 */
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
 * Handle POST /admin/profile-sessions, wired to
 * selfservice.flows.settings.after.profile without can_interrupt, which Kratos
 * runs after it persists the new traits. Same bearer and body as the gates;
 * `session_id` is the session that saved. Every other active session of the
 * identity is ended through the admin API. The profile change has already
 * persisted, so a failure here is logged and still answered 200: a non-2xx
 * would only show the member an error for a saved change. Without a
 * `session_id` nothing is ended, so the saving session is never cut.
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
  const kratosAdminURL = process.env.KRATOS_ADMIN_URL ?? '';
  if (typeof id !== 'string' || !id.trim() || typeof keep !== 'string' || !keep.trim() || !kratosAdminURL) {
    console.error(`${tag} identity_id, session_id or KRATOS_ADMIN_URL missing; other sessions left active`);
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
  if (method === 'POST' && path === '/admin/username-gate') {
    await handleUsernameGate(req, res, runtime);
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

  // Anything else (including every public/challenge path, and a served admin
  // path on the wrong method) is not found on the admin port.
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
  // The standalone entry.mjs auto-binds its OWN server on import unless this
  // is set: @astrojs/node's start() is a no-op when ASTRO_NODE_AUTOSTART is
  // "disabled". We want only this module to bind sockets (public + admin), so
  // disable the adapter's auto-start and drive the exported `handler` directly.
  process.env.ASTRO_NODE_AUTOSTART = 'disabled';
  const { handler: ssrHandler } = await import('./entry.mjs');
  return http.createServer((req, res) => {
    ssrHandler(req, res, (err) => {
      // `next` for unmatched routes / errors: the middleware handler did not
      // produce a response. Emit a plain 404/500 rather than hanging.
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
 * Fail-closed startup checks (pure; test helper). Empty/short secret or a
 * wildcard ADMIN_HOST each push a FATAL message; caller decides what to do.
 *
 * - RECOVERY_GATE_SECRET empty or <32 bytes UTF-8 → bearer check on
 *   /admin/recovery-gate would reject every request (fail-closed is correct),
 *   but that is always operator misconfiguration; refuse to boot so the
 *   problem surfaces immediately rather than silently degrading the gate.
 *   32-byte floor mirrors csrf.ts's CSRF_SECRET check (CRYPTO-2).
 * - ADMIN_HOST is a wildcard (0.0.0.0, :: or empty "") → admin port would be
 *   exposed to the network; the admin mux has no public-facing auth hardening
 *   and must only be reachable on loopback or a pod-internal address. Note the
 *   `?? '127.0.0.1'` default only catches null/undefined, NOT an empty string —
 *   ADMIN_HOST="" reaches http.listen as the IPv6 wildcard, and "::" is the
 *   explicit IPv6 wildcard. Both must be refused alongside 0.0.0.0.
 */
export function startupEnvErrors() {
  const errors = [];

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

  if (ADMIN_HOST === '0.0.0.0' || ADMIN_HOST === '::' || ADMIN_HOST === '') {
    errors.push(`[portal] FATAL: ADMIN_HOST is a wildcard address (${JSON.stringify(ADMIN_HOST)}) — the admin port must be bound to loopback or a pod-internal IP, never a wildcard (0.0.0.0, :: or empty)`);
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

// Bind both listeners only when run as the entrypoint (not when imported by
// tests, which exercise the pure admin mux above).
if (import.meta.url === `file://${process.argv[1]}`) {
  assertStartupEnv();

  const publicServer = await createPublicServer();
  publicServer.listen(PORT, HOST, () => {
    console.log(`[portal] public listener on http://${HOST}:${PORT}`);
  });

  const adminServer = createAdminServer();
  adminServer.listen(ADMIN_PORT, ADMIN_HOST, () => {
    console.log(`[portal] admin listener on http://${ADMIN_HOST}:${ADMIN_PORT}`);
  });

  // ── In-process OIDC client reconciler ────────────────────────────────────
  // In-process OIDC client reconciler. Both listeners are
  // already bound (healthz is green) BEFORE reconciliation begins, so a slow
  // or failing Hydra never delays the portal coming up.
  //
  // Boot: bounded retry+backoff (reconcileOnBoot). After the retry budget is
  // exhausted the portal logs a clear operator notice and keeps serving; an
  // operator SIGHUP retries once Hydra is ready.
  //
  // SIGHUP: drops the manifest cache (re-reads from disk) then reconciles.
  // Errors are swallowed — the portal always continues serving.
  const registrar = await import('./registrar.mjs');
  registrar.reconcileOnBoot().catch((e) => console.error('[portal] boot reconcile error', e));
  process.on('SIGHUP', () => {
    registrar.reloadOnSighup().catch((e) => console.error('[portal] SIGHUP reload error', e));
  });
}
