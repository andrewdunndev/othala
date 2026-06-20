// GET/HEAD /api/forward-auth — Caddy `forward_auth` authorization endpoint for
// NON-OIDC apps that can't participate in the login/consent flow but sit behind
// the same Caddy edge and the same Kratos session cookie.
//
// Caddy is configured roughly as:
//
//   forward_auth othala-portal:PORT {
//       uri /api/forward-auth?group=access-observe
//       copy_headers X-Kratos-Authenticated-Identity-Id
//   }
//   @denied status 401
//   handle_response @denied {
//       redirect https://dag.dunn.dev/auth/login?return_to={uri}
//   }
//
// The endpoint decides ALLOW/DENY purely from the Kratos session and the
// admin-managed access group. It is SECURITY-SENSITIVE AUTHZ and FAILS CLOSED:
// any missing precondition, malformed input, or upstream error denies.
//
// Status contract (the body is advisory; Caddy keys on the STATUS):
//   200 "ok"             — valid session, identity active AND in the group
//   401 "unauthenticated" — no/invalid Kratos session (Caddy → login redirect)
//   403 "forbidden"      — everything else: missing/bad group param, identity
//                          lookup failure, inactive identity, not in the group
//
// Why 401 vs 403 matters: 401 is the ONLY status Caddy turns into a login
// redirect. A logged-in user who simply lacks the group must get 403 (a flat
// "forbidden"), NOT a redirect loop back through login. So we 401 ONLY when
// there is no usable session, and 403 for every authorization failure.
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
import type { Identity } from '../../lib/types';

export const prerender = false;

// Operator-set access group name. This is an INPUT GUARD (SSRF/charset), not a
// naming policy: othala imposes no group-naming convention (access-model Phase
// 3, docs/access-model.md §10/§11). Any adopter-named group passes as long as it
// matches the safe charset; the group's MEANING comes from a manifest binding,
// never its name. (`access-observe` and bare `observe` both pass.)
const GROUP_RE = /^[a-z0-9][a-z0-9-]*$/;

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
  //    if absent/empty or not within the safe charset (input guard, not a
  //    naming policy).
  const group = url.searchParams.get('group')?.trim() ?? '';
  if (group === '' || !GROUP_RE.test(group)) {
    return text(403, 'forbidden');
  }

  // 2. Verify the Kratos session from the request's own Cookie header.
  //    No usable session → 401 (the only status Caddy turns into a login
  //    redirect). A thrown error (Kratos unreachable) is NOT a 401 — that
  //    would loop the user through login against a broken backend — so we
  //    fail closed to 403.
  const cookie = request.headers.get('cookie') ?? undefined;
  let identityId: string | undefined;
  try {
    const session = await getSession(cookie);
    if (!session?.active || !session.identity?.id) {
      return text(401, 'unauthenticated');
    }
    identityId = session.identity.id;
  } catch {
    return text(403, 'forbidden');
  }

  // 3. Resolve the identity via the ADMIN API to read state + metadata_admin
  //    .groups (neither is in the public whoami). Lookup failure → 403
  //    (fail-closed): a session existed, so this is an authz failure, not a
  //    "please log in".
  let identity: Identity;
  try {
    identity = await getIdentity(identityId);
  } catch {
    return text(403, 'forbidden');
  }

  // 4. The canonical gate: state === "active" AND membership in `group`.
  const gate = enforceGroupGate(identity, group);
  if (!gate.allowed) {
    return text(403, 'forbidden');
  }

  // 5. Allow. Surface the identity id for downstream apps that consume it.
  //    We only ever SET this header from a server-verified id; the endpoint
  //    never reads/trusts an inbound identity header.
  return text(200, 'ok', { [ID_HEADER]: identityId });
}

export const GET: APIRoute = ({ request, url }) => decide(request, url);

// HEAD must apply the IDENTICAL authz decision (a HEAD that 200s where the GET
// would 403 is an auth bypass). Astro/undici will drop the body for us, but we
// reuse decide() verbatim so the status + headers are guaranteed identical.
export const HEAD: APIRoute = ({ request, url }) => decide(request, url);
