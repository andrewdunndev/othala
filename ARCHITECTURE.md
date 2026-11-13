# Architecture

Why the pieces are arranged the way they are. What each one does is in the code and the tests named below.

## Components

| Piece | Role |
|---|---|
| **Kratos** | Identity. Self-service login, recovery, verification, settings, credentials. Public API through the edge; admin API pod-internal only. |
| **Hydra** | OAuth2 / OIDC. Issues tokens; ships no UI and no authorization model by design. Public API through the edge; admin API pod-internal only. |
| **Postgres** | Separate databases for Kratos and Hydra. |
| **The app** (`portal/`) | Everything Ory leaves to the integrator: Hydra's login and consent providers, the access gate, the claims builder, the forward-auth endpoint, the client registrar, the admin UI, and the rendered Kratos self-service pages. |
| **The edge** | A reverse proxy terminating TLS and routing one hostname across the three upstreams. The image ships the routes and the app gates as snippets (`caddy/othala.caddy`); the site address and TLS are the deployment's. |

It is one application because every one of those concerns needs an Ory **admin** API, which must never
be reachable from the network. One process keeps every admin-API caller inside one trust domain and
adds no service-to-service authorization problem.

```mermaid
flowchart LR
  browser([Browser / app client]) --> edge[Edge proxy<br/>TLS, one hostname]
  subgraph pod[One trust domain: the admin APIs never leave it]
    app[The app<br/>public SSR listener + internal-network admin listener (PORTAL_ADMIN_BIND_HOST)]
    kratos[Kratos]
    hydra[Hydra]
    pg[(Postgres)]
  end
  edge --> app
  edge -->|self-service, sessions| kratos
  edge -->|authorize, token, discovery| hydra
  app -->|admin API| kratos
  app -->|admin API| hydra
  kratos --> pg
  hydra --> pg
```

## Trust boundary

**The network sees three ports:** Kratos public, Hydra public, and the app's public SSR port. Neither
admin API is exposed, and no app in front of this stack is given an admin credential.

**The app runs two listeners in one process** (`portal/src/server/listen.ts`). The public listener
serves the Astro handler. The admin listener binds `PORTAL_ADMIN_BIND_HOST` with its own
mux (the `ADMIN_GET` and `ADMIN_POST` maps) that never delegates to the Astro handler. SECURITY.md
owns the listener controls and their tests.

**Inbound headers are never an identity claim.** Group membership and identity id come from Kratos,
never from a request header. Every snippet in `caddy/othala.caddy` first deletes the inbound identity
id and every header in the `Remote-*`, `X-Remote-*`, `X-Forwarded-User*`, `X-Auth-Request-*`,
`X-Webauth-*` and `X-Authentik-*` families, so the upstream receives only the id taken from the auth
response. Each snippet is a `route` block because Caddy's
default directive order would otherwise run `forward_auth` ahead of `request_header` and strip the
verified id. Of the cookies, `othala-oidc-app` removes only the Kratos session cookie.

**Admin authority is a marker, not a group.** Kratos strips `metadata_admin` from `/sessions/whoami`, so
`parseIdentity` (`portal/src/lib/identity-facts.ts`) reads it only from an identity fetched fresh from the
admin API; the three-part admin check is in [SECURITY.md](SECURITY.md).

## The access model

Entry and role are separate bindings, and nothing is derived from a name.

**Entry** comes from an access group, always. A manifest's `presentation.access` list is the entry
binding; `parseAccessGroups` (`portal/src/lib/access-groups.ts`) normalizes it into `accessGroups`,
and membership in any one of them admits (OR-semantics). Only this grants entry.

**Role** comes from *additionally* holding a group that the same manifest's `consent.group_role_map`
maps to a declared role. A role-mapped group grants no entry of its own: an identity holding only the
role group is denied at the gate before any claim is composed.

Nothing else participates: no `access-<clientId>` name is synthesized, and
admin does not imply access. A group's *type* is a property of its bindings, never of its spelling;
`portal/src/lib/group-registry.ts` derives it (`identity` from the configured identity-group list,
`access` from an entry binding, `role` from a role map). `e2e/playwright/tests/t-access-model.spec.ts` (T1 through T10) pins it, including the same matrix at the forward-auth edge.

`enforceAccessGate` (`portal/src/lib/gate.ts`) evaluates in a fixed order:

1. **identity present**: a failed lookup denies;
2. **`state === 'active'`**: exactly that string, anything else denies;
3. **every stored group is canonical** (`refuseNonCanonical`);
4. **`skip_access_check`**, if the manifest sets it, bypasses only what follows;
5. **membership in a bound access group.**

Steps 2 and 3 sit above the escape hatch because they are facts about the identity, not one app's
binding; no manifest may waive them.

**The group-name policy.** `GROUP_RE` in `portal/src/lib/access-groups.ts` is the one canonical form
a group name may take anywhere in the app. No prefix is required; one definition lets every
group comparison use raw strings. Every write path enforces it (`validateGroups` in
`portal/src/lib/metadata-admin.ts`, the manifest loader, the lint, the forward-auth query parameter).
Step 3 above is the *read* boundary. Kratos's admin API is a write path this codebase does not own, so a
name no owned boundary could produce denies every app and names the group; repair is `planGroupSave`
(`portal/src/lib/gate.ts`), which refuses to write while a non-canonical name is held.

**Role resolution is order-independent.** `lookupRole` (`portal/src/lib/claims.ts`) takes a per-client
override if it names a declared role, and otherwise maps every held group through `group_role_map`
and keeps the role ranked highest by its index in `manifest.roles`. A first-match walk over stored
order would hand an identity holding both entry and role groups the lesser role. The
consent path and the admin UI's effective-access view share this one resolver.

## The forward-auth request path

For apps with no OIDC support. The edge makes a subrequest before passing traffic through, and the
answer is computed entirely from the Kratos session and the admin-managed groups.

1. The edge calls `GET`/`HEAD /api/forward-auth?group=<name>`, forwarding the original request's
   cookies. The required group is **static edge configuration**, never client input.
2. The parameter is checked against `GROUP_RE`. Absent, empty, or malformed denies.
3. The Kratos session is verified from the request's own `Cookie` header.
4. The identity is re-fetched through the Kratos **admin** API by the session's identity id, because
   neither `state` nor `metadata_admin.groups` appears in the public whoami.
5. `enforceGroupGate` applies steps 1 through 3 and 5 of the gate above, with no escape hatch:
   forward-auth has no manifest to grant one.
6. On allow, the response carries the identity id in a header set from the server-verified value.

`GET` and `HEAD` share one `decide` function, because a `HEAD` that answers differently from the `GET`
is an authorization bypass.

### The status contract

The body is advisory; the edge keys on the status.

| Status | Meaning |
|---|---|
| **200** | Allow. |
| **401** | No usable session, or aal2 step-up due. |
| **403** | Refused, either on the merits (inactive identity, a non-canonical stored group, or a group miss) or for a missing or malformed `group` parameter. 403 does not mean one thing. |
| **503** | Kratos or its admin API did not answer. |

The malformed parameter is a broken deployment, static per site, not an outage, so it is not a 503.

**Why 503 is separate.** Caddy's `forward_auth` treats any non-2xx as a denial, so fail-closed is
unchanged either way. The separation lets an edge keep an outage out of its redirect arm: an edge
matching `status 401 403` into a login redirect would, if outages arrived as 403, bounce the visitor
to the login page of the app that just failed to answer, on every retry.
`othala-forward-auth` leaves 503 out of that matcher for this reason.

Failure paths are pinned by `portal/scripts/forward-auth.test.mjs`, the redirect-only-on-401 snippet by `portal/scripts/othala-caddy.test.mjs`.

## The OIDC path

`handleLogin` and `handleConsent` (`portal/src/lib/oauth2-handlers.ts`) are what Hydra redirects to.

On a login challenge, the subject is resolved and then gated. When Hydra reports `skip` (it remembers
this subject), the handler still re-verifies a live Kratos session matching the
remembered subject. Hydra only remembers; Kratos authenticates. Honouring a remembered login after a
Kratos sign-out would sign the subject in again silently.

A denial is logged server-side with its real reason and rejected upstream with an opaque
`access_denied`, so group names and identity-state distinctions never reach the relying party.

On consent, the gate runs again, and the id_token
claims are composed by `composeIDTokenClaims` (`portal/src/lib/claims.ts`): identity claims, then the
groups claim dropped unless the manifest opts in and narrowed to the groups that manifest binds, then the resolved role's `claim_emit` merged in,
then any claim whose required scope was not requested removed.

The `picture` claim (profile scope) exists only when a member has a picture. The image lives in
`metadata_admin.avatar`, so the identity schema is untouched, and is served unauthenticated at a content-addressed
`/avatar/<identity>/<hash>` because relying-party servers fetch it themselves; a new picture is a new URL.

A device grant (RFC 8628) arrives on the same two challenges after the code is entered at
`/device/verify`; Hydra marks it only by its device verification path in `request_url`, and the
handlers add the controls in [`SECURITY.md`](SECURITY.md) § Controls.

Revocation is one in-process fan-out, `revokeSubject` (`portal/src/lib/revoke.ts`), shared by admin
force-logout, user sign-out-everywhere, and deactivation. Kratos sessions and Hydra's remembered
login and consent sessions are all cut, because a remembered
Hydra login would otherwise still mint fresh tokens. Portal sign-out and narrowing someone's access run the Hydra
half alone. There is no identity cache, so a deactivated subject fails the state check on the next request.

## OIDC client registration

Hydra's client list is reconciled from the manifests.
`registerAllClients` (`portal/src/lib/register-clients.ts`) narrows the catalog to manifests that
declare an `oidc:` block, runs the full manifest lint, and then, per client, reads the
current state from Hydra to decide create versus update. Only `oidc:`-derived fields cross the wire;
the `consent:` block is a namespace this app owns and Hydra never sees it. Registration is
create-or-update only and never deletes, so a decommissioned client survives until removed deliberately.

Tokens already issued keep the claims they were minted with, so a manifest edit that changes who may enter or what the tokens say
must end them. Each client keeps a fingerprint of its access-relevant fields in its Hydra metadata; when it differs, the
reconcile revokes that client's consent sessions for every identity before storing the new one, so a restart loses nothing.
A client othala registered whose manifest is gone is revoked once and marked retired, but only from a complete load: a
quarantined file, an empty set or an unreadable directory proves nothing absent (`portal/scripts/register-revoke.test.mjs`).

`portal/src/server/registrar.ts` drives it on boot with capped-backoff retry until Hydra answers
and again on `SIGHUP`. A registration failure never takes down the listeners, so the admin surface stays
up to diagnose it.

## Manifests and failure posture

Manifests are read at request time behind a short cache, so adding or removing an app needs no image
rebuild. A file that fails to parse or validate, or shares a
`client_id` with another, is dropped and logged while the rest keep serving, so one bad edit cannot
500 every OIDC login and the admin UI; the dropped app is an unknown client and is refused. The lint
CLI still fails on an invalid file. `portal/src/lib/manifest-store.ts` covers the one remaining
failure, an unreadable directory: it keeps serving the last known good set and reports `stale`
through `manifestHealth`, or the empty set with none, which is fail-closed because the gate denies a
client whose manifest is missing. It retries on every call, so recovery needs no restart.

## Configuration and the one-way choices

One image serves any instance; `OTHALA_*` variables define the deployment, and `.env.example` is the
annotated contract. Ory does not expand `${VAR}` in its own files, so `kratos/kratos.yml`,
`hydra/hydra.yml` and `kratos/courier/` are templates, carried in the image and rendered by
`portal/src/lib/render.ts` (`node dist/server/config.mjs render`), which
derives the required variable set from the template itself and fails listing missing *names* only,
never rendered content that could carry a secret into a log. The e2e harness and the deploy plane
call the same render.

The one-way choices (issuer, apex, subject type) are in [DEPLOY.md](DEPLOY.md#before-the-first-enrolment).
