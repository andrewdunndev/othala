# consent

Small Go HTTP service that handles Hydra OAuth2 login, consent, and logout challenges. Runs alongside Hydra on carmine. Never publicly exposed; only reachable via Hydra's redirects, which the user's browser follows back to this service through Caddy on `auth.dunn.dev`.

## Why this exists

Hydra needs a "login app", a "consent app", and a "logout app" to handle the corresponding challenge redirects. The standard pattern would be: Hydra redirects the browser to our Astro UI, which calls the Hydra admin API to accept or reject.

Historical context: an earlier iteration of the project ran the Astro UI on Cloudflare Workers (edge), which physically couldn't reach Hydra's admin port (auth.network-internal). The consent service was the workaround. Since v0.1.3, the Astro portal runs as Node SSR on carmine inside the same pod network — but the consent service stays because the architectural split (browser-facing UI vs. Hydra-admin-touching glue) is still right. The portal handles user-facing concerns; consent handles "talk to Hydra's admin API to accept/reject the challenge."

Topology today:

- Astro portal runs on carmine (Node SSR), in the auth.network namespace.
- Hydra admin port (4445) is auth.network-internal. Never exposed publicly.
- Consent service co-located on the same network, reachable from Caddy at `auth.dunn.dev/{login,consent,logout}`.

The user sees a brief redirect through `auth.dunn.dev` (the same hostname they already see for the login flow). No exposure of admin internals.

## Endpoints

| Listener | Path | Purpose |
|---|---|---|
| public `:4477` | `GET /login?login_challenge=<id>` | Login challenge handler. If Hydra reports `skip`, accept with the remembered subject. Otherwise validate the Kratos session via cookie; if active, accept with `subject = identity.id`; if not, redirect to the home portal login UI with `return_to`. The `access-<client_id>` group gate fires here too, so a user without the entry group is rejected before consent. |
| public `:4477` | `GET /consent?consent_challenge=<id>` | Consent challenge handler. Enforces the `access-<client_id>` group, then auto-accepts for trusted clients (`skip_consent: true`). Rejects untrusted clients with `consent_required` (no consent UI in v1). Injects `email`, `email_verified`, `name`, `preferred_username`, `groups`, plus per-app role claims when the client manifest declares them. |
| public `:4477` | `GET /logout?logout_challenge=<id>` | Logout challenge handler. Always accepts; Kratos session invalidation is handled by the portal logout button hitting Kratos public `/self-service/logout`. Per-app session revocation goes through `/admin/revoke-user`. |
| public `:4477` | `GET /healthz` | Liveness check. |
| admin `:4478` | `POST /admin/revoke-user` | Admin endpoint (bearer-gated). Body: `{"subject": "<identity_id>"}`. Revokes every Kratos session for the identity, invalidates the in-process identity cache, and (MEDIUM-5) flushes the LDAP bridge bind cache when `LDAP_BRIDGE_ADMIN_URL` is configured. OIDC back-channel logout to the RPs is delivered by Hydra NATIVELY on admin session revocation (the portal's `revokeSubject` calls `revokeOAuth2LoginSessions` + `revokeOAuth2ConsentSessions`), not by this endpoint. |
| admin `:4478` | `POST /webhooks/recovery-gate` | Kratos `can_interrupt` hook. Pod-internal only. Rejects email-recovery flows for any identity in the `admin` group (D3). MEDIUM-2: requires `X-Webhook-Auth: <RECOVERY_GATE_SECRET>` header; constant-time compared. |
| admin `:4478` | `GET /healthz` | Admin-listener liveness check. |

## Listener split (MEDIUM-1)

Two listeners, two muxes:

```
:4477 (public, behind Caddy on auth.dunn.dev)
  /login, /consent, /logout, /healthz

:4478 (admin, pod-internal only, NOT proxied by Caddy)
  /admin/revoke-user, /webhooks/recovery-gate, /healthz
```

Caddy is configured to route `/login`, `/consent`, `/consent/*`,
`/logout`, `/logout/*` to the public mux and nothing else. The admin
mux is reachable only from inside the auth pod (Kratos for the
recovery-gate webhook, the portal for revoke-user). A future Caddy
edit that accidentally adds `/admin/*` to the upstream chain still
hits an empty 404 because the public mux does not register those
paths.

## Access-* group enforcement (D2)

Every OIDC client expects callers to be in `access-<client_id>` before
the consent service issues an id_token. The check fires in BOTH
`handleLogin` (when Hydra reports `skip`, against the remembered
subject; when not, against the active Kratos whoami) AND
`handleConsent` (after `GetIdentity`).

Failure mode: the gate calls Hydra's reject endpoint with
`error=access_denied` and `error_description="User is not in
access-<client_id> group"`. Hydra surfaces the failure to the app's
configured callback as the OAuth2 error response.

Override per client by setting `consent.skip_access_check: true` in
the yaml. Today only `llm` (machine-to-machine vLLM) sets it; the
client_credentials grant has no end-user identity, so the check is a
no-op.

This makes access-* the canonical OIDC entry gate, removing the gap
where apps that don't read the `groups` claim (Vaultwarden mainline,
BookLore) could otherwise admit any signed-in family member.

## Admin endpoints

`POST /admin/revoke-user` and `POST /webhooks/recovery-gate` are bound
to the ADMIN listener (default `:4478`), separate from the public
listener (`:4477`) that hosts `/login`, `/consent`, `/logout`,
`/healthz`. The split (MEDIUM-1) removes the ambient risk that a future
Caddy edit would expose `/admin/*` publicly: the admin port is
network-isolated to the auth pod and Caddy is configured to proxy only
the public mux.

Defense-in-depth on top of network isolation:

- `/admin/revoke-user` is bearer-gated by `CONSENT_ADMIN_BEARER`.
  Constant-time compare; fail-closed when unset.
- `/webhooks/recovery-gate` verifies the shared `RECOVERY_GATE_SECRET`
  presented as the `X-Webhook-Auth` header (MEDIUM-2). Constant-time
  compare; fail-closed when unset.
- The portal admin UI at `/admin/users/<id>` includes a "Force
  re-login" button. The portal's `revokeSubject` fan-out (CU3) drives
  the Kratos + Hydra admin revocation directly; Hydra then delivers the
  back-channel logout tokens to the RPs natively.

Rotation (operator runbook): replace the env var on the consent
quadlet, restart, then update the portal env binding. Both endpoints
fail-closed during the brief window where the values disagree.

## Back-channel logout

OIDC Back-Channel Logout 1.0 (§ 2.4–2.6) is delivered by **Hydra
natively** (oryd/hydra:v26.2.0). When sessions are revoked via the
admin API — `revokeOAuth2LoginSessions({subject})` +
`revokeOAuth2ConsentSessions({subject})`, which the portal's
`revokeSubject` fan-out (CU3) calls — Hydra signs a logout token with
its own id_token key and POSTs it to each client's
`backchannel_logout_uri`. RPs verify it against the same
`/.well-known/jwks.json` they already trust for id_tokens. No external
service needs Hydra's private key.

The consent service used to hand-roll this (fetch Hydra's private
id_token key from `/admin/keys/hydra.openid.id-token`, sign a
`logout+jwt`, POST it per-RP). That custom signer was removed (DAG CU4)
once it was confirmed Hydra has done BCL natively since 2019; native
delivery owns this path now.

Apps that don't support back-channel logout (Tailscale, vLLM, BookLore,
Jellyfin SSO plugin v3.x) leave `backchannel_logout_uri` empty and are
not registered for it; their local session expires on its own (per-app
cookie TTL).

## Architecture notes

- One non-stdlib dependency: `gopkg.in/yaml.v3` for parsing client manifests. All Hydra and Kratos calls are still hand-rolled `net/http`. The Ory SDKs work but are large; the API surface here is small enough that maintaining hand-rolled clients is cheaper than tracking SDK churn.
- All trusted clients (currently 14, manifests in `hydra/clients/*.yaml`) have `skip_consent: true`. The consent handler always grants `requested_scope` for trusted clients; per-app authorization happens in the apps using the `groups` claim.
- Hydra does not auto-populate OIDC claims from Kratos. Consent acceptance is the only place these claims get injected. See `claims.go` for the mapping rules.
- Login decisions are remembered for 24h. Consent decisions for 1h (mostly belt-and-suspenders since trusted clients skip).
- ACR from the Kratos session is forwarded into the login accept body so apps that care about AAL can read it from `id_token.acr`.

## ID token claim mapping

| Claim | Source |
|---|---|
| `email` | `identity.traits.email` |
| `email_verified` | `verifiable_addresses[email].verified` (omitted if no record) |
| `name` | `identity.traits.displayName`, fallback `identity.traits.username` |
| `preferred_username` | `identity.traits.username` |
| `groups` | `identity.metadata_admin.groups` (string array) |
| `sub` | Set by Hydra from the login subject (= `identity.id`) |
| per-app role claims | Merged from the resolved role's `claim_emit` map in `hydra/clients/<client_id>.yaml` (see below). |

Missing fields are omitted, not emitted as null.

## Per-app role mapping (v2)

Each client manifest declares two top-level blocks:

- `oidc:` — Hydra-bound. `apply-clients.sh` extracts this block and
  posts it (plus `client_secret` from env) to the Hydra admin API.
- `consent:` — consent-service-only. Holds `roles`, `group_role_map`,
  `emit_groups_claim`, and the `skip_access_check` escape hatch. NEVER
  forwarded to Hydra.

The namespace split (D6 / C3) keeps unknown fields from leaking into
Hydra's client object.

When `consent.roles` is non-empty, the consent service resolves a
single role per user per client and merges the role's `claim_emit` map
into the id_token alongside the standard claims (including `groups`,
which keeps emitting for back-compat).

Manifest shape (excerpt from `hydra/clients/keep.yaml`):

```yaml
oidc:
  client_id: keep
  client_name: Vaultwarden
  # ... standard OIDC fields ...
  audience:
    - https://keep.dunn.dev
  backchannel_logout_uri: https://keep.dunn.dev/identity/connect/oidc-logout

consent:
  emit_groups_claim: true
  roles:
    admin:
      description: Vaultwarden admin
      claim_emit:
        role: admin
        vw_admin: true
    user:
      description: Vaultwarden user
      claim_emit:
        role: user
  group_role_map:
    admin: admin
    family: user
    kids: user
```

Identity shape (in `metadata_admin`):

```json
{
  "groups": ["family", "access-keep"],
  "roles": { "keep": "admin", "larder": "user" }
}
```

### Resolution algorithm

For each consent challenge against client `X`:

1. **Override.** If `metadata_admin.roles.X` is set and names a role declared in the client's `roles` block, use it.
2. **Derive.** Walk `metadata_admin.groups` in declared order. For each group, look it up in the client's `group_role_map`. The first group that maps to a role declared in `roles` wins.
3. **Skip.** If neither produces a match, no role-specific claims are emitted. The consent flow still accepts and still emits `groups` (back-compat, unless suppressed; see below).

### Optional flags

```yaml
emit_groups_claim: false   # default true
```

When `false`, the default `groups` claim is dropped from the id_token
for that client. Only set this when an app explicitly does not consume
groups and the extra claim is unwanted (Tailscale custom OIDC ignores
groups entirely; vLLM is client_credentials and issues no id_token at
all). The role's `claim_emit` is still merged; only the auto-emitted
`groups` from the default claim set is suppressed.

### Claim emission semantics

The id_token claims sent to Hydra are built in three steps:

1. **Auto claims.** `BuildIDTokenClaims` populates the standard set
   (`email`, `email_verified`, `name`, `preferred_username`, `groups`)
   from the Kratos identity. `sub` is set by Hydra from the login
   subject, not here.
2. **Optional groups suppression.** If the client manifest has
   `emit_groups_claim: false`, the auto `groups` claim is removed.
3. **Role claim merge.** If a role resolves for the user via the
   manifest's `roles` + `group_role_map`, its `claim_emit` map is
   deep-merged into the id_token claims.

The merge is recursive at `map[string]any` boundaries:

- A key present in `claim_emit` but not in the existing claims is added.
- Two nested maps are merged recursively at the leaf path. Sibling keys
  in the existing claim are preserved.
- Two arrays at the same path: last-write-wins (the role's array
  replaces the existing one). We do not array-union; only one role
  applies per user per client, so overlap is rare and well-defined.
- Scalar conflict at the same path: role wins. Role's `claim_emit`
  overrides the auto-emitted claim.

Example (flat, Mealie):

```yaml
roles:
  user:
    claim_emit:
      mealie_role: user
```

Result, before merge:

```json
{ "email": "...", "groups": ["family"] }
```

After merge:

```json
{ "email": "...", "groups": ["family"], "mealie_role": "user" }
```

Example (nested, Vaultwarden mainline future shape):

```yaml
roles:
  admin:
    claim_emit:
      groups: ["admin"]
      resource_access:
        keep:
          roles: ["admin"]
```

Result, before merge:

```json
{ "email": "...", "groups": ["family", "access-keep"] }
```

After merge:

```json
{
  "email": "...",
  "groups": ["admin"],
  "resource_access": { "keep": { "roles": ["admin"] } }
}
```

The `groups` claim was overridden by the role (last-write-wins);
`email` was preserved; `resource_access` was added.

Notes:

- The walk uses the order of `groups` in the user's identity, not the order of keys in `group_role_map`. yaml map ordering on the client side does not affect resolution.
- An override that names an undeclared role (typo) falls through to derivation rather than emit nothing. This keeps an admin typo from silently stripping a user's access.
- A manifest without a `roles` block is the v1 shape. The consent service skips role injection and emits the standard claims only.

### CLI: validate manifests

The consent binary doubles as a manifest linter:

```sh
go build -o consent .
./consent --validate-manifests --manifest-dir ../hydra/clients
```

Exit codes: `0` clean, `1` IO/parse error, `2` lint findings (e.g., `group_role_map` pointing at a role that's not declared, or a role with no `claim_emit`).

### Hot reload

The running service reloads manifests on `SIGHUP`. A failed reload (parse error, duplicate `client_id`) is logged and the previous in-memory state is left intact.

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `PUBLIC_LISTEN` | `:4477` | Public mux listen address (`/login`, `/consent`, `/logout`, `/healthz`). Falls back to `CONSENT_LISTEN` if set; the older name is preserved for back-compat. |
| `ADMIN_LISTEN` | `:4478` | Admin mux listen address (`/admin/*`, `/webhooks/*`). Pod-internal; never proxy publicly. |
| `CONSENT_PUBLIC_URL` | (empty) | Public scheme+host (no trailing slash). When set, `buildReturnTo` uses it instead of trusting `r.Host` / `r.TLS`. Required behind Caddy doing TLS termination. HIGH-2 mitigation. |
| `HYDRA_ADMIN_URL` | `http://hydra:4445` | Hydra admin API base URL. Internal-only. |
| `KRATOS_PUBLIC_URL` | `http://kratos:4433` | Kratos public API. Used for `/sessions/whoami` with cookie passthrough. |
| `KRATOS_ADMIN_URL` | `http://kratos:4434` | Kratos admin API. Used for identity lookup during consent. |
| `LOGIN_URL` | `https://auth.dunn.dev/auth/login` | Where to redirect users without a Kratos session. `?return_to=` appended. |
| `HYDRA_CLIENT_DIR` | `../hydra/clients` | Directory of `*.yaml` manifests to load at startup and on `SIGHUP`. The `--manifest-dir` flag overrides this. |
| `CONSENT_ADMIN_BEARER` | (empty) | Bearer token gating `/admin/*` endpoints. Empty disables the admin endpoints entirely (fail-closed). |
| `RECOVERY_GATE_SECRET` | (empty) | Shared secret Kratos sends as `X-Webhook-Auth` on the recovery-gate webhook. Empty disables the webhook (fail-closed). MEDIUM-2. |
| `LDAP_BRIDGE_ADMIN_URL` | (empty) | If set, consent flushes the LDAP bridge bind cache after a revoke (MEDIUM-5). Empty = skip silently (lab without bridge). |
| `LDAP_BRIDGE_ADMIN_BEARER` | (empty) | Bearer for the bridge admin endpoint. MUST be set when `LDAP_BRIDGE_ADMIN_URL` is. |

Logging is structured JSON via `log/slog` to stdout.

## Run locally

```sh
go build -o consent .
./consent
curl -s http://localhost:4477/healthz
```

## Build the image

```sh
make build
make verify   # smoke-tests /healthz
```

## Test in the lab

The consent service comes up as a container in the lab compose stack on the same network as Hydra and Kratos.

```sh
# in lab/
docker compose up -d hydra kratos consent
# trigger an OIDC flow against any registered client; browser will land on
# auth.dunn.dev/login?login_challenge=... -> consent service -> back to Hydra
```

Watch logs:

```sh
docker compose logs -f consent
```

Each accept/reject is logged with `subject`, `client`, and `scope` for tracing.

## Deployment

Production (carmine): runs in a quadlet alongside the Hydra pod. Caddy in front of `auth.dunn.dev` routes `/login`, `/consent`, and `/logout` to this service; everything else to Hydra.

Lab (GCP): runs as a container in the compose stack on the same network as Hydra and Kratos.

## Future

If we ever want a consent UI for untrusted clients (third-party OAuth2 apps not in the trusted whitelist), this service grows a "render consent screen" path that returns HTML instead of redirecting. Out of scope for v1; today it rejects with `consent_required`.
