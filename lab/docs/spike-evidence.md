# Phase 1 lab spike — evidence

**Date:** 2026-05-03
**VM:** auth-lab-1777772733 (e2-standard-2, Fedora Cloud 42, us-central1-a)
**Lab domain:** auth-lab.34-16-5-84.sslip.io / keep-lab.34-16-5-84.sslip.io
**Stack:** Kratos v1.3.0 + Hydra v2.2.0 + Postgres 16 + reference UIs (kratos-selfservice-ui-node v1.3.0, hydra-login-consent-node v2.2.0) + Caddy 2.8 + Vaultwarden 1.30.5
**Tester:** Andrew Dunn, macOS Firefox

## Verdict: GREEN

The Ory Kratos + Hydra substrate is viable for our locked architecture. WebAuthn ceremony works, TLS chain validates against rp.id, schema migrations work as init containers, multi-component routing through Caddy works. Phase 2 (LDAP bridge build) is unblocked.

## What was validated

### GREEN

| Check | Evidence |
|---|---|
| Stack starts cleanly | All 7 containers (postgres, kratos-migrate init, hydra-migrate init, kratos, hydra, kratos-ui, login-consent, vaultwarden, caddy) reach healthy state |
| Schema migrations as init containers | hydra-migrate + kratos-migrate exit 0; main services depend_on `service_completed_successfully` |
| Caddy HTTP-01 → Let's Encrypt | `https://auth-lab.34-16-5-84.sslip.io/` and `keep-lab.34-16-5-84.sslip.io/` issue real LE certs without Cloudflare in path |
| WebAuthn ceremony fires | Touch ID prompt appears in Firefox; credential enrolled |
| WebAuthn login succeeds | Logout → /login → username + passkey → authenticated session |
| `rp.id` correctly scoped | `34-16-5-84.sslip.io` parent assertable from `auth-lab.34-16-5-84.sslip.io` origin |
| Hydra OIDC discovery | `/.well-known/openid-configuration` returns valid metadata, JWKS reachable |
| Hydra client registration | `keep-lab` OIDC client created via admin REST API + import JSON |
| Multi-component routing through Caddy | `/login` query-param disambiguates Kratos vs Hydra; `/.well-known/ory/*` reaches Kratos correctly; static assets reach kratos-ui |
| Identity model (username/email/displayName + metadata_admin) | Schema validated, identity created, password + WebAuthn credentials slots populated |

### YELLOW (Phase-2/3 work, not blockers)

| Finding | Implication |
|---|---|
| Reference kratos-ui (v0.21.3) requires typed username at login | Production Astro UI must use the **`passkey` method** (not `webauthn passwordless`) for true conditional-UI / discoverable-credential login. This matches the locked decision in STATUS.md. |
| Vaultwarden 1.30.5 SSO route 404s | Vaultwarden upstream stabilized SSO in v1.32+; bump version when wiring carmine. Substrate plumbing (Hydra clients, OIDC discovery) is fine. |
| AAL2 step-up (lab-spike t5) | Skipped in this spike. Production Astro requireAdminSession() needs the actual flow tested before carmine cutover. |

### Encountered gotchas (now documented for production cutover)

1. **Kratos `${VAR}` interpolation does NOT work in YAML.** Lab uses `envsubst` to render `kratos.lab.yml` → `kratos.rendered.yml` before mounting. Production pyinfra needs the same render step.
2. **Kratos minimum password length is 6** (schema floor); cannot go below for testing.
3. **Cipher secret length validates ≥32 chars exactly.** Use `openssl rand -hex 16` (32 hex = 32 chars), NOT base64 alnum-stripped (variable length).
4. **`required_aal` is no longer valid in `flows.login` config** (Kratos v1.3 schema change). Removed from lab config; production should track this when bumping versions.
5. **Hydra v2 `hydra create client --id <X>` flag does not exist.** Use admin REST API POST or `hydra import oauth2-client <file>` to set explicit client_id.
6. **Hydra schema migrations are NOT auto.** Must run `hydra migrate sql -e --yes` before `hydra serve`. Same for Kratos. Both as init containers in production.
7. **Kratos courier should be a singleton** (not in this spike — no recovery flow tested — but documented in production STATUS.md).
8. **Vaultwarden requires `I_REALLY_WANT_VOLATILE_STORAGE=true`** when run without persistent volume.
9. **Caddy route order matters.** `*.js` glob in kratos-ui matcher catches `/.well-known/ory/webauthn.js`; well-known/ory route must come first.
10. **kratos-ui `BASE_URL` does NOT mount express under prefix.** Use Caddy `handle_path` to strip prefixes, or unprefixed Kratos `ui_url`s with query-param disambiguation against login-consent.
11. **kratos-ui makes server-side calls to KRATOS_PUBLIC_URL.** On GCP VMs, the public DNS doesn't hairpin-NAT back. Must set `KRATOS_PUBLIC_URL=http://kratos:4433` (internal) and `KRATOS_BROWSER_URL=https://...` (browser-facing) separately.

### NOT validated in this spike (deferred)

- Kratos↔Hydra integration via our own consent service (Phase 3)
- LDAP bridge (Phase 2)
- Astro UI (Phase 3)
- Recovery flow + courier (Phase 3)
- iOS Safari WebAuthn second-device (deferred — fully expected to work given macOS Firefox passes)

## Validated identity in lab

- Username: `agd`
- Email: `agd@dunn.dev`
- Credentials: password (`labpass1`) + WebAuthn passkey
- Identity ID: `53922877-2cf4-4ad9-9243-0492653f7123`

(All thrown away on VM teardown.)

## Recommended Phase 2 priorities

1. **Build glauth-kratos plugin** (the bulk of Phase 2 — the spike unblocks this).
2. When that's running in lab, validate Jellyfin LDAP bind against the bridge (the substrate proves Kratos `/sessions/whoami` works; the bridge translates BIND to that flow).

## Cost

VM ran ~75 minutes, ~$0.10 per the e2-standard-2 rate.

## Next gate

t39 done → t40 (Phase 2: glauth-kratos plugin) ready to claim.
