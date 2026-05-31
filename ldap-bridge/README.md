# glauth-kratos

LDAP bridge to Ory Kratos. Translates LDAP BIND and SEARCH operations to Kratos public-API and admin-API calls. Identities live in Kratos; this bridge presents them over LDAP for clients that need the LDAP protocol (Jellyfin's LDAP plugin for Apple TV / Infuse).

## Status

Phase 2 implementation in place. Code compiles, unit tests pass, binary boots and parses the sample config. Lab validation against a live Kratos is the next step. See `../docs/STATUS.md` for the broader project state.

## Why this binary, not a glauth fork

glauth v2.4 has no public handler-registration API. Backends are wired by a hard-coded switch on `backend.Datastore` in `pkg/server`, the `embed` path is build-tag gated to sqlite, and the `plugin` path opens runtime `.so` files (which fights distroless and CGO). The cleanest path is to own the entrypoint: this binary links `github.com/glauth/ldap` (the same LDAP server library glauth uses) and registers our Kratos handler directly. The handler still implements glauth's `pkg/handler.Handler` interface, so it remains drop-in for any future upstream registration API.

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
  public_url_env = "KRATOS_PUBLIC_URL"
  admin_url_env  = "KRATOS_ADMIN_URL"
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

If the bridge proves out in production, extract the `kratos/` package and its scaffolding to its own repo: `gitlab.com/dunn.dev/glauth-kratos` (or a GitHub mirror). Submit to glauth as a contribution: a public handler-registration API would let this slot in without forking. Generally useful for any Kratos consumer needing LDAP.
