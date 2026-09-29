// GET/HEAD /api/forward-auth — Caddy `forward_auth` authorization endpoint for
// NON-OIDC apps that can't participate in the login/consent flow but sit behind
// the same Caddy edge and the same Kratos session cookie.
//
// An edge that uses this endpoint points `forward_auth` at the portal and
// passes the required group as a static query param, roughly:
//
//   forward_auth <portal-upstream> {
//       uri /api/forward-auth?group=<group>
//       copy_headers X-Kratos-Authenticated-Identity-Id
//
//       @unauth status 401 403
//       handle_response @unauth { ... }
//   }
//
// othala ships NO snippet of that shape. caddy/snippets/forward-auth.caddy
// points `forward_auth kratos:4433` at `uri /sessions/whoami` and "establishes
// ONLY that a valid Kratos session exists" — it passes no group and never
// reaches this route.
// That is the session-only archetype; this endpoint is the session-AND-group
// one, and the edge config that calls it is written per site.
//
// The endpoint decides ALLOW/DENY purely from the Kratos session and the
// admin-managed access group. It is SECURITY-SENSITIVE AUTHZ and FAILS CLOSED:
// any missing precondition, malformed input, or upstream error denies.
//
// Status contract (the body is advisory; Caddy keys on the STATUS):
//   200 "ok"             — valid session, identity active AND in the group
//   401 "unauthenticated" — no/invalid Kratos session, or an aal1 session
//                          that must step up to aal2 (lib/step-up.ts)
//   403 "forbidden"      — the request was refused on its merits: inactive
//                          identity, a NON-CANONICAL STORED GROUP on the
//                          identity (refuseNonCanonical in
//                          portal/src/lib/gate.ts, against GROUP_RE in
//                          portal/src/lib/access-groups.ts), not in the group,
//                          or a missing/malformed operator `group` param
//   503 "unavailable"    — the endpoint could not establish the facts: Kratos
//                          or the Kratos admin API did not answer
//
// Why 503 is a separate status. Caddy's forward_auth expands to a
// reverse_proxy with `@good status 2xx`, and "if the upstream responds with
// any other status code, then the upstream's response is copied back to the
// client" (caddyserver.com/docs/caddyfile/directives/forward_auth) — so 503
// denies exactly as 403 does, and the fail-closed posture is unchanged. What
// it buys is that 403 no longer covers an outage: an edge rendering a deny
// page from a 403 can name the required group without that page appearing
// during an identity-provider outage, and an edge matching `@unauth status
// 401 403` no longer bounces an outage into a login loop against the same
// portal that is down.
//
// 403 still covers one non-authz case: a missing or malformed `group` param.
// That is operator config, static per site, and denies every request to that
// site rather than one person's — it is a broken deployment, not an outage.
//
// What this endpoint does NOT control: whether a denial becomes a login
// redirect. That is the EDGE's decision, made by its `status` matcher plus
// `handle_response` — a status this endpoint returns is redirected iff the
// site's matcher lists it. An edge matching `status 401 403` redirects on
// BOTH, while an edge matching `status 401` alone lets a 403 through as a flat
// deny.
//
// Why the endpoint still separates them: it is the only way the edge CAN
// choose. Collapsing everything to 401 would remove the distinction between
// "you are not signed in" and "you are signed in and not permitted", and a site
// that wants the second case to render a flat 403 instead of bouncing an
// already-signed-in user back through login could no longer express it.
// Read the site's Caddyfile before reasoning about what a user actually sees.
//
// Group source — NEVER trust inbound headers:
//   - The required group comes from the `group` QUERY PARAM, which is set by
//     Caddy's static config (operator-controlled), not by the client.
//   - The user's groups come from metadata_admin.groups, which is admin-only
//     and NOT present in the public whoami. We therefore re-fetch the identity
//     via the ADMIN API by the session's identity id and read state + groups
//     from that. We never read an inbound X-*-Group / identity header.

import type { APIRoute } from 'astro';
import { getSession } from '../../lib/kratos';
import { getIdentity } from '../../lib/admin';
import { enforceGroupGate } from '../../lib/gate';
import { GROUP_RE } from '../../lib/access-groups';
import { needsStepUp } from '../../lib/step-up';
import type { Identity, Session } from '../../lib/types';

export const prerender = false;

// GROUP_RE (portal/src/lib/access-groups.ts) IS the naming policy — the one
// canonical form a group name may take anywhere in the portal, enforced at
// every boundary this codebase owns. It used to be defined here as a local
// input guard on this parameter alone. It still says nothing about a group's
// TYPE: that comes from its bindings, never its name, so `access-metrics` and
// bare `metrics` both pass.

const ID_HEADER = 'X-Kratos-Authenticated-Identity-Id';

function text(status: number, body: string, headers: Record<string, string> = {}): Response {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      // Authz decisions are per-request and must never be cached by any hop.
      'Cache-Control': 'no-store, max-age=0',
      ...headers,
    },
  });
}

async function decide(request: Request, url: URL): Promise<Response> {
  // 1. Required group from the (operator-controlled) query param. Fail closed
  //    if absent/empty or not in the canonical form. 403, not 503: this is a
  //    static misconfiguration of the site, not an upstream that stopped
  //    answering.
  const group = url.searchParams.get('group')?.trim() ?? '';
  if (group === '' || !GROUP_RE.test(group)) {
    return text(403, 'forbidden');
  }

  // 2. Verify the Kratos session from the request's own Cookie header.
  //    No usable session → 401, the status that MEANS "send this person to
  //    login" (whether the edge acts on it is the edge's matcher — see the
  //    status contract above). A thrown error (Kratos unreachable) is neither
  //    a 401 nor a 403: it is not a statement about the user at all. Fail
  //    closed to 503.
  const cookie = request.headers.get('cookie') ?? undefined;
  let identityId: string | undefined;
  let session: Session | null;
  try {
    session = await getSession(cookie);
    if (!session?.active || !session.identity?.id) {
      return text(401, 'unauthenticated');
    }
    identityId = session.identity.id;
  } catch {
    return text(503, 'unavailable');
  }

  // 3. Resolve the identity via the ADMIN API to read state + metadata_admin
  //    .groups (neither is in the public whoami). A throw here → 503
  //    (fail-closed): we never learned this identity's state or groups, so we
  //    cannot say "not authorised" about it. Every throw takes this branch,
  //    including a 404 — telling a 404 from a 500 would mean depending on the
  //    @ory/client-fetch error shape, and a 404 on an id a live session just
  //    vouched for is no more an authz answer than a 500 is.
  let identity: Identity;
  try {
    identity = await getIdentity(identityId);
  } catch {
    return text(503, 'unavailable');
  }

  // 4. The canonical gate (lib/gate.ts): state === "active", no non-canonical
  //    stored group, AND membership in `group`. 403 here is the one meaning
  //    left to it — authenticated, and not authorised.
  const gate = enforceGroupGate(identity, group);
  if (!gate.allowed) {
    return text(403, 'forbidden');
  }

  // 5. Step-up: the same rule as app sign-in. 401 sends the person back to
  //    the login page, which asks for the second factor (auth/login.astro).
  if (needsStepUp(session, identity)) {
    return text(401, 'unauthenticated');
  }

  // 6. Allow. Surface the identity id for downstream apps that consume it.
  //    We only ever SET this header from a server-verified id; the endpoint
  //    never reads/trusts an inbound identity header.
  return text(200, 'ok', { [ID_HEADER]: identityId });
}

export const GET: APIRoute = ({ request, url }) => decide(request, url);

// HEAD must apply the IDENTICAL authz decision (a HEAD that 200s where the GET
// would 403 is an auth bypass). Astro/undici will drop the body for us, but we
// reuse decide() verbatim so the status + headers are guaranteed identical.
export const HEAD: APIRoute = ({ request, url }) => decide(request, url);
