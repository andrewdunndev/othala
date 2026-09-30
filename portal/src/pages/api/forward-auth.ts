// GET/HEAD /api/forward-auth: Caddy `forward_auth` endpoint for non-OIDC apps; the edge passes the required group as
// `?group=`. SECURITY-SENSITIVE, fails closed, trusts only the Kratos session and admin-managed groups, never inbound headers.
// Status (Caddy keys on it): 200 valid session, active identity in the group; 401 no/invalid session or aal1 needing
// step-up; 403 refused on merits (inactive, non-canonical stored group, not in the group, bad `group` param);
// 503 Kratos or its admin API did not answer, so a 403 never means an outage. Login redirects are the edge's matcher.

import type { APIRoute } from 'astro';
import { getSession } from '../../lib/kratos';
import { getIdentity } from '../../lib/admin-api';
import { enforceGroupGate } from '../../lib/gate';
import { GROUP_RE } from '../../lib/access-groups';
import { needsStepUp } from '../../lib/step-up';
import type { Identity, Session } from '../../lib/types';

export const prerender = false;

// The group name policy is GROUP_RE (access-groups.ts); a group's type comes from its bindings, so `access-metrics` and `metrics` both pass.

const ID_HEADER = 'X-Kratos-Authenticated-Identity-Id';

function text(status: number, body: string, headers: Record<string, string> = {}): Response {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store, max-age=0',
      ...headers,
    },
  });
}

async function decide(request: Request, url: URL): Promise<Response> {
  // 1. Required group from the operator-controlled query param; fail closed if absent or non-canonical. 403, not 503:
  //    a misconfigured site, not an upstream outage.
  const group = url.searchParams.get('group')?.trim() ?? '';
  if (group === '' || !GROUP_RE.test(group)) {
    return text(403, 'forbidden');
  }

  // 2. Verify the session from the request's Cookie. None: 401 (send to login). A throw is no statement about the
  //    user, so fail closed to 503.
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

  // 3. Resolve the identity via the ADMIN API (state and metadata_admin.groups are not in whoami). Every throw,
  //    404 included, is 503: we never learned the state or groups, so we cannot say "not authorised".
  let identity: Identity;
  try {
    identity = await getIdentity(identityId);
  } catch {
    return text(503, 'unavailable');
  }

  // 4. The canonical gate (gate.ts); 403 means authenticated and not authorised.
  const gate = enforceGroupGate(identity, group);
  if (!gate.allowed) {
    return text(403, 'forbidden');
  }

  // 5. Step-up, same rule as app sign-in: 401 sends the person to login for the second factor.
  if (needsStepUp(session, identity)) {
    return text(401, 'unauthenticated');
  }

  // 6. Allow; the identity id header is only ever SET from a server-verified id.
  return text(200, 'ok', { [ID_HEADER]: identityId });
}

export const GET: APIRoute = ({ request, url }) => decide(request, url);

// HEAD reuses decide() so it can never 200 where GET would 403.
export const HEAD: APIRoute = ({ request, url }) => decide(request, url);
