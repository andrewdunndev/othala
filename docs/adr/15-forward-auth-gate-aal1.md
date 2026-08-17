# 15 — Forward-auth gate, and why `session.whoami` stays aal1

## Status

Accepted (2026-08-15). Browser apps that cannot speak OIDC are gated by Caddy
`forward_auth` calling the portal, and `session.whoami.required_aal` in
`kratos/kratos.yml` **must stay `aal1`** because that gate reads `whoami`.

This record exists because the constraint was nearly deleted as dead code. The
only written justification for the setting named the glauth→Kratos LDAP bridge,
which was retired having never run — and a live setting whose sole stated reason
is a shelved feature looks exactly like cleanup. It is not. The bridge's
retirement changes nothing here; the consumer that makes the setting load-bearing
is the forward-auth route, and it has been in production the whole time.

See also [01](01-auth-substrate-ory.md) (forward_auth is one of the three ways a
service authenticates here), [08](08-admin-authority-model.md) (where AAL2 *is*
enforced), [09](09-capability-group-access-model.md) (the groups this gate reads),
[11](11-hardening-tuning.md) (the settings-flow AAL setting, which is a different
setting), and [13](13-vendored-config-contract.md) (editing `kratos.yml` is a
re-vendor).

## Context

Not every app can be an OIDC client. Some have no OIDC support at all, some have
it only behind a licence, and some are single-binary web UIs with a hardcoded
login form. These apps still sit behind the same Caddy edge and are still reached
by browsers that already carry the apex-scoped Kratos session cookie.

Caddy's `forward_auth` covers this: before proxying, Caddy asks an authorization
endpoint whether this request may proceed, and turns the answer into allow, deny
or login-redirect. The endpoint has to answer from the session cookie alone,
because the app behind it has no idea who the user is.

Two facts make the endpoint's job specific. First, the group memberships that
decide access live in `metadata_admin.groups`, which is admin-API-only and does
**not** appear in the public `whoami` response — so knowing the session is valid
is not enough. Second, Caddy distinguishes statuses, not bodies, and it is the
*edge site* that decides which of those statuses becomes a login redirect: the
endpoint returns a status, the site's `status` matcher and `handle_response`
turn it into a redirect or a flat deny. The endpoint's job is therefore to make
the two failure kinds distinguishable, not to pick the outcome.

## Decision

**The gate.** `portal/src/pages/api/forward-auth.ts` exposes `GET` and `HEAD` at
`/api/forward-auth`. Caddy calls it with the required group as a **static query
parameter** set by the edge config — `?group=<svc>-access` — never as an inbound
header. The route:

1. Reads `group` from the query string and validates it against a safe charset
   (the `GROUP_RE` constant in `portal/src/pages/api/forward-auth.ts`). This is an **input
   guard, not a naming policy**: the route enforces nothing about what a group is
   called, matching [09](09-capability-group-access-model.md), where the
   `<svc>-access` style is *UNENFORCED — convention only*.
2. Verifies the Kratos session from the request's own `Cookie` header.
3. Re-resolves the identity **via the admin API** by the session's identity id, to
   read `state` and `metadata_admin.groups` — neither of which is in `whoami`. It
   never reads an inbound `X-*` identity or group header.
4. Applies `enforceGroupGate` (`portal/src/lib/gate.ts:73-87`): identity present,
   `state === 'active'`, and membership in the named group.
5. On allow, returns 200 and sets `X-Kratos-Authenticated-Identity-Id` from the
   server-verified id.

**The status contract is load-bearing and deliberate:**

- **200** — valid session, identity active, in the group.
- **401** — *and only* for "no usable session". It is the endpoint's way of
  saying "this person needs to sign in".
- **403, fail closed** — everything else: missing or malformed group parameter,
  Kratos unreachable, identity lookup failure, inactive identity, group miss.

So an outage is never *reported* as "please log in", and a logged-in user who
simply lacks the group is distinguishable from one who has no session at all.
`HEAD` reuses the same `decide()` function verbatim, because a `HEAD` that 200s
where the `GET` would 403 is an authorization bypass.

**What the endpoint does not decide: whether a denial becomes a redirect.**
There is no status Caddy redirects on by default, and 401 is not privileged: a
status this endpoint returns is redirected iff the edge's own `status` matcher
lists it. Three shapes follow from that, and which one a deploying edge uses is a
property of the deployment, not of this route:

| edge matcher | what a denial looks like |
|---|---|
| `status 401 403` | both statuses redirect — a group miss bounces to login the same as a session miss |
| `status 401` alone | the 401 redirects; a 403 passes through as a flat deny |
| no status matcher, no `handle_response` | no status is listed, so nothing redirects, on any status |

Neither of the first two is wrong; they are different answers to "should a denied
visitor be offered a login they may have already completed, or told plainly no",
and the matcher keys off the status code alone, never off *why* the denial
happened. What IS wrong is reading this record and concluding that a 403 cannot
produce a redirect. Read the deploying edge's own Caddyfile before predicting
what a user sees, and treat the redirect-loop argument below as the reason the
endpoint keeps the statuses distinct — not as a guarantee about what any
particular edge does with them.

This repo ships no Caddy snippet for this route. `caddy/snippets/forward-auth.caddy`
is a session-only gate: its `forward_auth` targets Kratos directly (`uri
/sessions/whoami`), and its own header sends non-OIDC apps that need group checks
to "a dedicated forward_auth endpoint that resolves group membership server-side
via the Kratos admin API and returns 200/403". Nothing under `caddy/` passes a
`group` parameter — `grep -rn "group=" caddy/` returns nothing — so there is no
in-repo example of the shape described above.

![The forward-auth request path: a browser carrying the apex-scoped session cookie reaches the estate edge and the service's Caddy, which sub-requests the portal's /api/forward-auth with the required group before proxying; the portal verifies the session, re-resolves the identity through the Kratos admin API, and answers 200, 401 or 403.](../../site/public/diagrams/forward-auth-request-path.svg)

**Why `whoami` must stay `aal1`.** The gate's session check is:

```ts
const session = await getSession(cookie);
if (!session?.active || !session.identity?.id) {
  return text(401, 'unauthenticated');
}
```

(Step 2 of `decide()` in `portal/src/pages/api/forward-auth.ts`.) The identity id is not a
convenience — it is the only input to step 3, so without it the gate has nothing
to look up.

`session.whoami.required_aal` is pinned `aal1` in `kratos/kratos.yml:264-272`.
Setting it to `highest_available` makes `whoami` stop returning a usable identity
for any session belonging to an identity that has enrolled a second factor. The
gate then takes one of two paths, and **both are lockouts**: a session object with
a null identity falls into the 401 branch above, while an error response is caught
and becomes a 403. Neither is survivable — at a site matching `401 403` both
become a bounce to login that returns the user to exactly the same state, so it
loops; at a site matching `401` only, the 401 loops and the 403 is a hard wall.
There is no third outcome where the gate recovers.

The blast radius is every app fronted by this gate, at once, and it lands
**only** on users who enrolled a second factor: the people who did the right
thing.

**AAL is enforced per flow instead, never at `whoami`:** AAL2 step-up on `/admin`
in the portal's server-side guard ([08](08-admin-authority-model.md)), and
`selfservice.flows.settings.required_aal: highest_available` on credential change
(`kratos/kratos.yml:144`, [11](11-hardening-tuning.md)). A 200 from `whoami`
therefore never implies aal2, and no code should read it that way — the admin
guard re-checks for itself.

## Consequences

- **The pin has no automated guard.** *UNENFORCED — convention only*: no CI gate,
  deploy check or e2e test asserts `session.whoami.required_aal: aal1`. What is
  enforced is the *coupling* — step 2 of `decide()` in
  `portal/src/pages/api/forward-auth.ts` treats a missing `session.identity.id`
  as unauthenticated, and that is real code on the request path. The value itself is protected by the comment beside it, by this
  record, and by nothing else. If a guard is ever added, it belongs in the deploy
  plane's checks, where the rendered config can actually be read.

- **Any future edit to that setting must trace the consumer first** — *UNENFORCED
  — convention only*. The consumer is this gate. Grep `getSession` and
  `forward-auth` before touching it.

- **If you find a note anywhere in this repo justifying the aal1 pin by the LDAP
  bridge, that note is stale.** The bridge is retired
  ([01](01-auth-substrate-ory.md)). The reason is this record. Correct the note,
  do not delete the setting.

- **Changing `kratos.yml` is a re-vendor.** It is one of the four byte-canonical
  files in [13](13-vendored-config-contract.md); an othala-side edit is not live
  until the deploy plane re-vendors it, and the deploy gate will redden in the
  meantime.

- **The portal is on the request path for non-OIDC apps.** Portal down means those
  apps are unreachable, full stop. What the user sees depends on the edge — a
  Caddy error where the upstream call itself fails, or a bounce to a login page
  that is served by the same portal and therefore also down — so do not rely on
  a specific status here. This is an availability cost accepted deliberately in
  exchange for a single place where access is decided.

- **The gate needs the Kratos admin API on every request.** That is what makes
  admin-only group data usable at the edge, and it is why the admin hop's network
  isolation ([03](03-proxy-originated-mtls.md)) matters to this path too. Kratos
  admin unreachable is a 403 for every gated app.

- **The required group is edge configuration, not app configuration.** The route
  reads it from the query param the deploying edge sets; which group fronts which
  app is therefore a property of that edge's config, and this record deliberately
  restates none of it. A path-scoped gate (admin group required only under
  `/admin`) is expressed the same way, as a second `forward_auth` block with a
  different `group`.

**Depends on:** `portal/src/pages/api/forward-auth.ts` (treats a missing
`session.identity.id` as 401) and `portal/src/lib/gate.ts` (`enforceGroupGate`).

## Alternatives considered

- **Set `whoami` to `highest_available` and teach the gate to cope.** Rejected
  because there is nothing to cope with: a null identity leaves the gate with no
  id to resolve, so it cannot read `state` or groups and cannot make an
  authorization decision at all. The only "fix" would be trusting something the
  request supplies, which is the failure mode the route is built to refuse.

- **Require AAL2 at the forward-auth gate itself.** Rejected: it would force
  second-factor enrolment on every household member for every gated app,
  including the ones a child uses on a shared tablet. Step-up belongs at the
  privileged surfaces — the admin UI and credential changes — where it is already
  enforced.

- **Trust a header from Caddy for the group or the identity.** Rejected
  explicitly, and the route's own comments say so: anything that can reach the
  portal can forge a header, and the portal is reachable from the pod network.
  The group comes from operator-controlled static config; the identity comes from
  a server-verified session.

- **Return 403 for everything, including no-session.** Rejected: it erases the
  "needs to sign in" signal, so an edge could no longer route a first visit to
  login without also routing every authorization failure and every backend
  outage there. Every first visit would look broken at any site that wanted a
  flat deny.

- **Return 401 for authorization failures too.** Rejected: it erases the signal
  in the other direction, leaving the edge no way to tell a group-miss apart
  from a missing session. A site that wants an already-signed-in user to see a
  plain "forbidden" could not express it, and the classic redirect loop —
  bounced to login, succeed, come back, bounced again, with no message naming
  the real problem — would become unavoidable rather than a choice. Note that a
  site matching `status 401 403` has effectively opted into that loop for
  group-misses already; the difference is that it remains the site's call and
  can be changed by editing one matcher.

- **Give every app an OIDC client instead.** That is the preferred answer wherever
  the app supports it ([01](01-auth-substrate-ory.md)); `forward_auth` exists for
  the apps that cannot. An app that can do neither re-opens the parked LDAP
  question rather than being let through ungated.
