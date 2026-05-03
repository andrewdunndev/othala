# glauth-kratos

Custom glauth binary with an embedded Kratos backend. Translates LDAP BIND and SEARCH operations to Ory Kratos public-API and admin-API calls. Identities live in Kratos; this bridge presents them over LDAP for clients that need the LDAP protocol (Jellyfin's LDAP plugin for Apple TV / Infuse).

## Status

Skeleton (Phase 0). Real implementation lands in Phase 2 of the build (see `../docs/STATUS.md`). The structure here is the contract — interfaces, config shape, deployment pattern.

## Why a custom glauth binary

glauth has a plugin/handler system; v2.5.0 (April 2026) added compile-time embedded plugins as the recommended path (vs runtime `.so` loading). We build a custom glauth binary with our Kratos handler imported as a side-effect import, registered via `init()`. Same direct-go-build pattern as the custom Caddy image.

## How it works

```
LDAP client (Jellyfin)
        │
        │ LDAPS bind / search
        ↓
glauth-kratos (this binary)
        ├─ Bind: POST <kratos>/self-service/login/api → /self-service/login?flow=...
        │       (verifies password by running a Kratos API-flow login)
        │       Cache positive results 30s to absorb reconnect storms.
        │
        └─ Search: GET <kratos>/admin/identities (paginated)
                  Project to LDAP entries:
                    dn:        uid=<traits.username>,ou=users,dc=dunn,dc=dev
                    uid:       traits.username
                    cn:        traits.displayName || traits.username
                    mail:      traits.email
                    memberOf:  [cn=<group>,ou=groups,dc=dunn,dc=dev for group in metadata_admin.groups]
                  Cache identity list 30s, refresh on stale read.
```

## Deployment shape

**Production (carmine):** co-located in the Jellyfin pod. LDAP traffic is localhost-to-localhost; bridge talks to Kratos over the inter-pod network. Smaller blast radius than a centralized LDAP server.

**Lab (GCP):** standalone container in the compose stack, exposed on the lab VM at 636/LDAPS for the Jellyfin app stub.

## Config

Wired via `glauth.cfg`:

```toml
[backend]
  datastore = "plugin"
  plugin = "kratos"

[backend.kratos]
  public_url = "http://kratos:4433"
  admin_url = "http://kratos:4434"
  admin_token_env = "KRATOS_BRIDGE_ADMIN_TOKEN"
  base_dn = "dc=dunn,dc=dev"
  identity_cache_ttl = "30s"
  bind_cache_ttl = "30s"
```

The `KRATOS_BRIDGE_ADMIN_TOKEN` env var carries the admin token. The token is scoped **identities:read** (read-only); the bridge cannot create, modify, or delete identities. This minimizes blast radius if the bridge is compromised.

## Risk mitigations (from feasibility-q1-kratos-bind.md)

| Risk | Mitigation |
|---|---|
| Kratos rate-limits per-identity logins, BIND storms trip them | Bind cache (30s TTL) absorbs Apple TV / Jellyfin reconnect bursts; only positive results cached |
| MFA-enabled identities return null in whoami when `required_aal=highest_available` | Kratos config sets `whoami.required_aal=aal1`; bridge uses login flow not whoami; aal=aal1 implicit at flow level |
| Kratos has no admin-API webhooks for identity CRUD | Identity cache polls every 30s; admin-driven changes propagate within one cycle (acceptable at homelab scale) |
| `/admin/identities` filtering is limited in OSS Kratos | We list-and-filter in the bridge for SEARCH operations (fine at family-of-25 scale) |
| Bridge holds admin API token, container compromise = admin access | Token scoped read-only via Kratos's per-token capability; can't do admin-level mutations |

## Build and test

```bash
make build       # podman build (or docker)
make verify      # run --help to confirm binary is healthy
make test        # go test ./kratos/...
```

## Upstream contribution path

If the bridge proves out in production, extract `kratos/` package (and the surrounding glauth-binary scaffolding) to its own repo: `gitlab.com/dunn.dev/glauth-kratos` (or github mirror). Submit to glauth as an embedded-plugin contribution. Generally useful for any Kratos consumer needing LDAP — meaningful upstream value.
