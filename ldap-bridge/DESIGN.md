# glauth-kratos: design

LDAP bridge to Ory Kratos. Translates LDAP BIND and SEARCH to Kratos
public-API and admin-API calls. Co-located with Jellyfin in production.

## Architecture choice

The skeleton assumed glauth has a `handler.Register(name, factory)` API.
It does not. glauth v2.5 wires backends with a hard-coded switch on
`backend.Datastore` (`config`, `ldap`, `owncloud`, `embed`, `plugin`).
The `embed` case is gated by build tags (`embedsqlite`, `embedmysql`)
and only ever calls `embed.NewSQLiteHandler`. The `plugin` case opens a
runtime `.so` via `plugin.Open`, which fights distroless and CGO.

So this binary does not embed glauth's `cmd` package. It links
`github.com/glauth/ldap` (the LDAP server library glauth itself uses)
and registers our handler's methods directly via `BindFunc`,
`SearchFunc`, `CloseFunc` on the server. The Kratos handler still
implements glauth's `Handler` interface (`pkg/handler.Handler`), so if
glauth grows a real registration API later, this package drops in
without code changes.

Net: the binary is glauth-shaped at the handler boundary, but owns its
own entrypoint and config loader.

## LDAP to Kratos mapping

| LDAP op | Kratos call | Notes |
|---|---|---|
| BIND `uid=X,ou=users,<base>` | `POST /self-service/login/api` then `POST /self-service/login?flow=<id>` with `method=password`, `identifier=X`, `password=<pw>` | 200 = success, 4xx = wrong creds, 5xx = unavailable |
| SEARCH (any filter) | `GET /admin/identities` (paginated via `page_token`) cached 30s | Bridge holds a list and applies the LDAP filter in-process |
| ADD / MODIFY / DELETE | nothing | Returns `LDAPResultUnwillingToPerform`. Identities are admin-managed via Kratos directly. |

## DN format

Locked decision E2: `uid=<username>,ou=users,<base_dn>`

Parse rules (`kratos/dn.go`):
- Lowercase and trim both DN and base.
- Require suffix `,ou=users,<base_dn>` exactly. Reject anything else.
- Require RDN prefix `uid=`. Reject anything else.
- The portion between `uid=` and `,ou=users,` is the username.
- Empty username is rejected.

Examples (with `base_dn = dc=dunn,dc=dev`):
- `uid=andrew.dunn,ou=users,dc=dunn,dc=dev` -> `andrew.dunn`
- `uid=jane,ou=users,dc=dunn,dc=dev` -> `jane`
- `cn=foo,ou=users,dc=dunn,dc=dev` -> error (wrong RDN attribute)
- `uid=,ou=users,dc=dunn,dc=dev` -> error (empty uid)

## Attribute mapping

A Kratos identity becomes a single LDAP entry. Trait names match the
production identity schema (`username`, `email`, `displayName`).

| LDAP attribute | Source | Notes |
|---|---|---|
| `dn` | `uid=<traits.username>,ou=users,<base>` | |
| `objectClass` | `[inetOrgPerson, posixAccount]` | posixAccount because Jellyfin's LDAP plugin probes for it |
| `uid` | `traits.username` | |
| `cn` | `traits.displayName` (fallback `traits.username`) | |
| `sn` | `traits.displayName` (fallback `traits.username`) | inetOrgPerson requires `sn` |
| `mail` | `traits.email` | |
| `memberOf` | `cn=<group>,ou=groups,<base>` for each group in `metadata_admin.groups` | |

Groups are admin-managed via `metadata_admin.groups` (locked decision).
A group entry returns from `FindGroup` with member DNs derived from the
union over all identities.

## Error mapping

| Source | LDAP result code |
|---|---|
| DN parse error | `LDAPResultInvalidDNSyntax` |
| Kratos 200 (login) | `LDAPResultSuccess` |
| Kratos 4xx (login) | `LDAPResultInvalidCredentials` |
| Kratos 5xx or transport error | `LDAPResultUnavailable` |
| Bridge timeout | `LDAPResultUnavailable` |
| ADD / MODIFY / DELETE | `LDAPResultUnwillingToPerform` |

## Cache

Two caches, both in-process, both `sync.RWMutex`-protected.

**Identity cache** (`cache.identityCache`):
- TTL 30s (configurable).
- Refreshed on read when stale. Concurrent refreshers serialize on the
  write lock and re-check freshness.
- On Kratos error, cache is not updated; stale entries are served. This
  keeps SEARCH alive during transient Kratos outages.
- Indexed two ways: by username (for `FindUser` and BIND DN lookup) and
  as an ordered slice (for SEARCH iteration).

**Bind cache** (`cache.bindCache`):
- TTL 30s (configurable).
- Keyed by `sha256(per_process_salt || username || NUL || password)`.
  The per-process salt (M3) prevents memory-dump replay across
  processes and pre-computed-table attacks. Salt is 32 random bytes
  initialized at startup.
- Positive results only. Negative results are not cached: a typo
  retried with the right password must succeed without waiting for
  TTL.
- Purpose: absorb Apple TV / Jellyfin reconnect storms where Argon2
  verification per-request would saturate Kratos.

### Cache lag posture (M4 / M5)

**Password rotation lag (M4):** A user who changes their password in
Kratos can still bind successfully against the bridge with the OLD
password for up to `BindCacheTTL` (default 30s). The bind cache
doesn't invalidate on password rotation; Kratos doesn't fire admin
webhooks, and we don't poll for credential generation changes.
Acceptable at homelab scale: 30 seconds of valid-old-password is in
the same envelope as the LDAP plugin's own session caching on the
consumer side (Jellyfin's session lifetime, etc.).

**Group-change lag (M5):** A user removed from `access-cinema` can
still appear in LDAP SEARCH results and bind successfully for up to
`IdentityCacheTTL` (default 30s) after the admin edit. For OIDC
flows the lag floor is higher: the consent service has its own 30s
identity cache, and Hydra remembers consent for 1h plus refresh
tokens valid for 30 days. The canonical fast-revocation path is
forced re-login via the admin "Revoke sessions" action on the user
page, which kills the Hydra-side remember and the Kratos session in
one move.

If revocation latency matters more than the cache benefits in a
future deployment, drop both TTLs to a few seconds; the cost is
higher Kratos admin-API load.

## Configuration shape

Loaded from the binary's own config file (TOML; same shape as
glauth.cfg for operator familiarity).

```toml
[ldap]
  enabled = false
  listen = "127.0.0.1:389"

[ldaps]
  enabled = true
  listen = "0.0.0.0:636"
  cert = "/etc/glauth/tls/cert.pem"
  key  = "/etc/glauth/tls/key.pem"

[backend]
  baseDN = "dc=dunn,dc=dev"

[backend.kratos]
  public_url        = "http://kratos:4433"
  admin_url         = "http://kratos:4434"
  admin_token_env   = "KRATOS_BRIDGE_ADMIN_TOKEN"
  base_dn           = "dc=dunn,dc=dev"
  identity_cache_ttl = "30s"
  bind_cache_ttl     = "30s"
```

Secrets are read from env vars referenced by `*_env` keys, never inline.
The admin token is scoped `identities:read`.

## What is not implemented yet

Deferred to lab work:
- Real TLS material (lab uses Caddy-issued LE certs already).
- Connection-rate limiting at the LDAP layer (Kratos does its own).
- Metrics / structured logging beyond stdlib `log`.
- AAL2 step-up. Bind always uses aal1; the spike confirms this is what
  Kratos's API flow returns.

## Anonymous bind handling (H10)

**Status:** documented, not implemented. User's stance is "Jellyfin LDAP
deferred for now; one month of manual user-add for the cinema app is
fine." The bridge's current behavior:

- `parseUsernameFromDN` rejects empty bind DN.
- `Bind` with an empty `bindSimplePw` falls through to Kratos's
  `/self-service/login/api` flow which Kratos refuses with 4xx
  (no anonymous identifier, no password). The bridge maps this to
  `LDAPResultInvalidCredentials`.

Net: Jellyfin's LDAP plugin currently fails on the first anonymous
bind probe. The plugin uses anonymous bind to discover the user DN
before re-binding with credentials, so it never gets to step two.

### Bind sequence Jellyfin's plugin issues

1. `BIND` (anonymous, empty DN, empty password)
2. `SEARCH` for the user under `ou=users,<base_dn>` filtered by uid
3. Read the resulting DN
4. `BIND` (the discovered DN, the user's password)
5. Optionally `SEARCH` for group memberships

Steps 1, 2, 5 are anonymous in the Jellyfin plugin's default config.

### Two viable patches (pick one when Jellyfin is wired in)

Patch A: allow anonymous bind to succeed empty
:   `Bind` returns `LDAPResultSuccess` for empty DN + empty password,
    and `Search` is allowed under an anonymous bound DN. The
    Jellyfin plugin proceeds to step 2 (search), gets the DN, then
    re-binds in step 4 with the user's password. Pro: no service
    credential to manage. Con: anyone can enumerate identities by
    LDAP search. At homelab scale this is acceptable; the bridge is
    not internet-reachable and the Jellyfin pod's network is the
    perimeter.

Patch B: configured service-account bind
:   The bridge accepts a service-account DN (e.g., `cn=jellyfin-svc,
    ou=services,<base_dn>`) and password from env vars, distinct from
    every Kratos identity. Jellyfin configures this as the bind DN.
    Pro: enumeration is gated behind a credential. Con: one more
    secret to rotate, the service-account password isn't a Kratos
    credential so rotation goes through pyinfra-managed env updates.

### Recommendation for the lab work

Patch A first; it's three lines in `parseUsernameFromDN` and `Bind`.
If lab security review flags identity enumeration as unacceptable at
the operator's threshold, swap to Patch B before family rollout. The
anonymous-bind path works for AD-style LDAP plugins (Jellyfin,
Nextcloud, others) without per-app service-account provisioning, which
is the more common shape.

Defer until Jellyfin is wired into the lab; the bind sequence above is
based on plugin source-code reading, not measured. Capture the actual
trace before picking the patch.

## Other open questions

- Filter evaluation: the simple substring/equality filters Jellyfin
  uses are fine through `github.com/glauth/ldap`'s built-in filter
  helper. More complex filters (extensible match) are untested.
