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
//       POST /admin/revoke-user       — admin force-logout fan-out (CU3 B1)
//       POST /admin/recovery-gate     — Kratos recovery-gate webhook (CU3)
//       POST /admin/login-gate        — Kratos login-gate webhook (CVP-P3)
//     It NEVER delegates to the Astro `handler`, so no public route and no
//     challenge provider is reachable on the admin port — and the public
//     handler never sees admin paths. The two muxes are disjoint.
//
//   Secret model (CU3): the overloaded `auth_internal_bearer` is split into
//   PURPOSE-NAMED secrets:
//     - OTHALA_ADMIN_ENDPOINT_BEARER  guards POST /admin/revoke-user
//     - RECOVERY_GATE_SECRET        guards POST /admin/recovery-gate
//   Both checks are CONSTANT-TIME (timingSafeEqual) and FAIL-CLOSED (an
//   unset secret rejects every request). The portal->consent admin HTTP hop
//   and CONSENT_ADMIN_BEARER are gone: the revoke fan-out is in-process.
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
export const ADMIN_POST_ROUTES = new Set(['/admin/revoke-user', '/admin/recovery-gate', '/admin/login-gate']);

/** Back-compat: the GET probe routes (CU1 contract test imports this name). */
export const ADMIN_ROUTES = ADMIN_GET_ROUTES;

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

/**
 * Decide the recovery-gate verdict for a Kratos webhook payload (pure).
 *
 * Kratos posts the in-flight identity to the gate before issuing a public
 * recovery code. We REFUSE recovery for any identity whose IMMUTABLE id is on
 * the OTHALA_ADMIN_IDS allowlist (admin recovery is console-only). The
 * `admin` metadata_admin group is NOT consulted (CVP-P1: display-only).
 *
 * The webhook payload shape is { identity_id, groups, traits } (see
 * kratos/hooks/recovery-gate.jsonnet). The id is read from identity_id at
 * the top level, falling back to identity.id for compatibility.
 *
 * FAIL-CLOSED on a malformed payload: if we cannot read a non-empty id,
 * refuse — a recovery webhook that can't identify the subject must not pass.
 *
 * @param payload parsed JSON body
 * @param isAdminId the id-allowlist predicate (injected from admin-runtime)
 * @returns { refuse: boolean, reason: string }
 */
export function recoveryGateVerdict(payload, isAdminId) {
  const id = payload?.identity_id ?? payload?.identity?.id;
  // Fail-closed: reject anything that is not a non-empty, non-whitespace-only
  // string. An unidentifiable subject must not pass.
  if (typeof id !== 'string' || id.trim().length === 0) {
    return { refuse: true, reason: 'unidentifiable subject (fail-closed)' };
  }
  if (isAdminId(id)) {
    return { refuse: true, reason: 'admin recovery is console-only' };
  }
  return { refuse: false, reason: '' };
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
 * Map a RevokeError dependency to an HTTP status. hydra/kratos admin
 * failures are upstream-dependency failures (502); anything else is 500.
 */
function statusForRevokeError(err) {
  const dep = err?.dependency;
  if (dep === 'hydra-admin' || dep === 'kratos-admin' || dep === 'ldap-bridge') return 502;
  return 500;
}

/**
 * Lazily load the runtime bundle (revokeSubject + isAdminId), compiled
 * from src/server/admin-runtime.ts to dist/server/admin-runtime.mjs by the
 * build. Cached after first import. Injected in tests so the admin handlers
 * can be exercised without the bundle.
 */
let _runtime = null;
async function loadRuntime() {
  if (_runtime) return _runtime;
  _runtime = await import('./admin-runtime.mjs');
  return _runtime;
}

/**
 * Handle POST /admin/revoke-user. Bearer: OTHALA_ADMIN_ENDPOINT_BEARER.
 * Body: { subject: string }. Runs the in-process revoke fan-out (steps 2-6,
 * deactivate=false). Prescriptive on upstream failure (dependency +
 * next-action), never leaking raw upstream errors.
 *
 * `runtime` is injectable for tests; defaults to the built bundle.
 */
export async function handleRevokeUser(req, res, runtime) {
  const expected = process.env.OTHALA_ADMIN_ENDPOINT_BEARER ?? '';
  if (!bearerMatches(parseBearer(req.headers?.authorization), expected)) {
    sendJson(res, 401, { error: 'unauthorized' });
    return;
  }
  let body;
  try {
    body = JSON.parse((await readBody(req)) || '{}');
  } catch {
    sendJson(res, 400, { error: 'invalid JSON body' });
    return;
  }
  const subject = typeof body?.subject === 'string' ? body.subject.trim() : '';
  if (!subject) {
    sendJson(res, 400, { error: 'missing "subject"' });
    return;
  }
  const rt = runtime ?? (await loadRuntime());
  try {
    const result = await rt.revokeSubject(subject);
    sendJson(res, 200, result);
  } catch (err) {
    // Prescriptive: surface dependency + the operator next-action carried by
    // RevokeError.message; never echo the raw upstream error/stack.
    sendJson(res, statusForRevokeError(err), {
      error: 'revoke failed',
      dependency: err?.dependency ?? 'unknown',
      step: err?.step ?? 'unknown',
      action: err?.message ?? 'retry the revoke',
    });
  }
}

/**
 * Handle POST /admin/recovery-gate. Bearer: RECOVERY_GATE_SECRET (constant-
 * time, fail-closed). Refuses recovery for allowlisted admin subjects;
 * fail-closed on a malformed payload. Returns the Kratos-webhook error shape
 * on refusal (HTTP 403 + messages), 200 on allow.
 *
 * `runtime` is injectable for tests; defaults to the built bundle.
 */
export async function handleRecoveryGate(req, res, runtime) {
  const expected = process.env.RECOVERY_GATE_SECRET ?? '';
  if (!bearerMatches(parseBearer(req.headers?.authorization), expected)) {
    sendJson(res, 401, { error: 'unauthorized' });
    return;
  }
  let body;
  try {
    body = JSON.parse((await readBody(req)) || '{}');
  } catch {
    // Fail-closed: an unparseable webhook body refuses recovery.
    sendJson(res, 403, {
      messages: [{ messages: [{ type: 'error', text: 'recovery refused: malformed payload' }] }],
    });
    return;
  }
  const rt = runtime ?? (await loadRuntime());
  const verdict = recoveryGateVerdict(body, rt.isAdminId);
  if (verdict.refuse) {
    sendJson(res, 403, {
      messages: [{ messages: [{ type: 'error', text: `recovery refused: ${verdict.reason}` }] }],
    });
    return;
  }
  sendJson(res, 200, { ok: true });
}

/**
 * Handle POST /admin/login-gate. Bearer: RECOVERY_GATE_SECRET (same
 * Kratos→portal admin-port trust domain as the recovery gate; no new secret).
 *
 * CVP-P3: Kratos fires this webhook on the `after.code` login hook before
 * issuing the session. We REFUSE login for admin identities whose immutable
 * identity id is on the OTHALA_ADMIN_IDS allowlist. Admins must use a passkey
 * or console, not email-code, which would yield an admin AAL1 session from
 * transient mailbox access.
 *
 * Fail-closed on unparseable body (403) and on unidentifiable subject (403).
 * Non-admin returns 200 { ok: true }.
 *
 * `runtime` is injectable for tests; defaults to the built bundle.
 */
export async function handleLoginGate(req, res, runtime) {
  const expected = process.env.RECOVERY_GATE_SECRET ?? '';
  if (!bearerMatches(parseBearer(req.headers?.authorization), expected)) {
    sendJson(res, 401, { error: 'unauthorized' });
    return;
  }
  let body;
  try {
    body = JSON.parse((await readBody(req)) || '{}');
  } catch {
    // Fail-closed: an unparseable webhook body refuses login.
    sendJson(res, 403, {
      messages: [{ messages: [{ type: 'error', text: 'login refused: malformed payload' }] }],
    });
    return;
  }
  const rt = runtime ?? (await loadRuntime());
  // Read identity id from the jsonnet payload shape { identity_id, groups, traits }
  const id = body?.identity_id ?? body?.identity?.id;
  if (typeof id !== 'string' || id.trim().length === 0) {
    sendJson(res, 403, {
      messages: [{ messages: [{ type: 'error', text: 'login refused: unidentifiable subject (fail-closed)' }] }],
    });
    return;
  }
  if (rt.isAdminId(id)) {
    sendJson(res, 403, {
      messages: [{ messages: [{ type: 'error', text: 'login refused: email-code login is disabled for admins — use a passkey or console' }] }],
    });
    return;
  }
  sendJson(res, 200, { ok: true });
}

/** Handle one admin-port request. Writes to res; never touches the SSR handler. */
export async function handleAdminRequest(req, res, runtime) {
  const method = req.method;
  const path = pathOf(req.url);

  if (method === 'GET' && ADMIN_GET_ROUTES.has(path)) {
    sendJson(res, 200, { status: 'ok' });
    return;
  }
  if (method === 'POST' && path === '/admin/revoke-user') {
    await handleRevokeUser(req, res, runtime);
    return;
  }
  if (method === 'POST' && path === '/admin/recovery-gate') {
    await handleRecoveryGate(req, res, runtime);
    return;
  }
  if (method === 'POST' && path === '/admin/login-gate') {
    await handleLoginGate(req, res, runtime);
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

// Bind both listeners only when run as the entrypoint (not when imported by
// tests, which exercise the pure admin mux above).
if (import.meta.url === `file://${process.argv[1]}`) {
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
