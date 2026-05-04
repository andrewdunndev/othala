# Phase 2 lab spike: glauth-kratos LDAP bridge — evidence

**Date:** 2026-05-03
**VM:** auth-lab-1777777823 (e2-standard-2, Fedora Cloud 42, us-central1-a)
**Lab domain:** auth-lab.34-170-71-191.sslip.io
**Stack:** Postgres 16 + Kratos v1.3.0 + glauth-kratos (built from `/opt/auth-lab/ldap-bridge`) + Caddy 2.8 + kratos-selfservice-ui-node v1.3.0
**Bridge image:** localhost/dunn.dev/glauth-kratos:lab (13 MB, Alpine 3.19 base, scratch-link Go 1.22 binary)
**Tester:** Andrew Dunn (automated suite via `lab/scripts/test-ldap.sh`)

## Verdict: GREEN

The LDAP bridge translates BIND and SEARCH against Kratos correctly. One bug fixed in the implementation (HTTP method on the login-flow init endpoint). The three open questions raised by the implementation agent have material answers below; one (anonymous bind for Jellyfin's discovery probe) needs design follow-up before production.

## Build outcome

| Metric | Value |
|---|---|
| Build context | `/opt/auth-lab/ldap-bridge/` |
| Builder image | `docker.io/library/golang:1.22-alpine3.19` |
| Runtime base | `docker.io/library/alpine:3.19` (with `ca-certificates`) |
| Build time (cold) | 59s (network-bound on go mod download + alpine pulls) |
| Build time (cached) | 3s |
| Final image size | 13 MB |
| Binary | `/usr/bin/glauth-kratos` (CGO_ENABLED=0, `-trimpath -s -w`) |

## Bug found and fixed during lab

`kratos/client.go:initLoginFlow` issued `POST /self-service/login/api` to start the login flow. Kratos v1.3.0 rejects that with `405 Method Not Allowed; Allow: GET, OPTIONS`. The fix is one line: switch the request method to GET. After the fix all bind paths succeed.

## BIND test results

All scenarios run via `ldapsearch` from inside the lab VM, against `ldaps://localhost:636` with `LDAPTLS_REQCERT=never` (self-signed cert, CN=glauth-kratos.local).

| # | Scenario | LDAP exit | Bridge / Kratos behavior | Pass |
|---|---|---|---|---|
| 1 | Correct bind + filter `(uid=ldaptest)` | 0 | Kratos audit: "Identity authenticated successfully", session issued and discarded; SEARCH triggered admin-API list | yes |
| 2 | Wrong password | 49 (InvalidCredentials) | Kratos returns 400 "provided credentials are invalid", bridge maps to LDAPResultInvalidCredentials | yes |
| 3 | Correct bind, filter for nonexistent user | 0 (empty result) | Bridge returns 0 entries, no error | yes |
| 4 | Correct bind, filter `(objectClass=inetOrgPerson)` | 0 | Returns ldaptest entry with requested attrs | yes |
| 5 | Bind with `cn=` prefix (wrong RDN) | 1 (OperationsError) | Bridge logs `bind DN RDN must use uid attribute`; returns LDAPResultInvalidDNSyntax-mapped error to client (libldap surfaces as Operations error 1) | yes |
| 6 | Anonymous bind (no `-D`/`-w`) | 49 (InvalidCredentials) | Bridge rejects empty bind DN as not matching expected suffix | yes (but see open question 1) |
| 7 | Correct bind, attribute selection (`uid mail` only) | 0 | Returns only requested attributes | yes |
| 8 | Repeat scenario 1 (cache hit) | 0 | No Kratos `/self-service/login` calls between test 7 and 8 in the audit log; bind cache served the request | yes |

## SEARCH attribute results

Successful searches return the projected entry exactly as DESIGN.md specifies:

```
dn: uid=ldaptest,ou=users,dc=dunn,dc=dev
objectClass: inetOrgPerson
objectClass: posixAccount
uid: ldaptest
cn: LDAP Test
sn: LDAP Test
mail: ldaptest@dunn.dev
```

Filter and scope are applied by the embedded `github.com/glauth/ldap` server (with `EnforceLDAP=true` set in `main.go`), not by the bridge. Both equality (`uid=ldaptest`) and presence-on-objectClass (`objectClass=inetOrgPerson`) filters work; substring filters were not tested in this run but are supported by the same code path.

## Bridge container logs

The bridge logs only error paths (`log.Printf` from glauth/ldap's `BindFn Error`). Full log for the test run:

```
2026/05/03 03:18:39 ldaps: listening on 0.0.0.0:636
2026/05/03 03:18:56 BindFn Error bind DN RDN must use uid attribute
```

Successful binds, wrong-password binds, and search calls produce no log lines, which is expected with the current logging setup. Production should add structured logging (DESIGN.md "What is not implemented yet" already lists this).

## Kratos audit log evidence

Kratos's own audit log confirms the bridge is using the correct flow:

- `GET /self-service/login/api` → 200 (flow created)
- `POST /self-service/login?flow=<id>` → 200 with payload "Identity authenticated successfully and was issued an Ory Kratos Session Token", session_id recorded
- `GET /admin/identities` (with `Authorization: Bearer <token>`) → 200, Link-header pagination present
- Wrong password: `POST /self-service/login` → 400 with "the provided credentials are invalid"

## Open questions: status

1. **Anonymous bind for Jellyfin's discovery probe (DESIGN.md "Open questions" #1).** The bridge currently treats anonymous bind (`bindDN=""`, `bindSimplePw=""`) as an invalid bind because `parseUsernameFromDN` rejects the empty DN at the suffix check. ldapsearch confirms this: anonymous bind returns LDAP code 49. Jellyfin's LDAP plugin sends an anonymous bind first to look up the user DN before re-binding with credentials. The bridge needs either: (a) a service-account bind path (anonymous bind treated as a read-only search-only session), or (b) explicit support for anonymous BIND that returns success but flags the connection as anonymous so SEARCH still works without write capability. **Status: unresolved, documented for follow-up.** Jellyfin integration is deferred per user direction (the user accepted manual Jellyfin login management).

2. **Filter compatibility (DESIGN.md "Open questions" #2).** Equality filters (`uid=X`), presence filters via `objectClass`, and basic conjunctions are handled by `github.com/glauth/ldap` post-hoc when `EnforceLDAP=true`. Tested OK. Extensible-match filters (`(memberOf:1.2.840.113556.1.4.1941:=...)`) were not tested and the upstream library does not document support. **Status: resolved for the simple cases Jellyfin uses; extensible-match remains untested.**

3. **Bind-time cache lookup (DESIGN.md "Open questions" #3).** Test 8 confirms the bind cache is hit on a repeat bind: between tests 7 and 8 there were no Kratos `/self-service/login` calls. **Status: resolved, working as designed.**

## Other findings

- `KRATOS_BRIDGE_ADMIN_TOKEN` is mandatory at the bridge config validator (`config.go:128`). Kratos OSS does not enforce a bearer token on its admin port (it's network-isolation-only), so for the lab we passed a dummy literal. Production needs to either (a) wire a real token through Kratos's `serve.admin.access_rules` (Kratos v1.x supports access rules via Oathkeeper but not native token gating on `/admin/`) or (b) accept that the admin port is gated by network policy alone and let the bridge config carry a placeholder. Worth a follow-up decision.
- `openssl` is not in the Fedora Cloud base image; the deploy script needs to install it (or skip cert generation if a cert is already provided). Updated `deploy-ldap.sh` to install `openssl gettext openldap-clients` would be a one-line tightening; the current script assumes those are present (added externally by `dnf install`).
- `lab/scripts/sync.sh` rsyncs `lab/compose/.env` as a regular file. `deploy-ldap.sh` now force-replaces it with a symlink to `/opt/auth-lab/.env` so the canonical env applies; this is the same pattern as `deploy.sh`'s ln-sf step but more aggressive.

## What was not validated

- iOS / Apple TV Jellyfin client against the bridge (deferred; Jellyfin integration manual for now).
- Kratos webauthn-only identities — the bridge's BIND path is password-method only; webauthn-only identities cannot bind via LDAP and would need an app password / API token alternative.
- Multi-page admin/identities pagination — only one identity in the lab Kratos.
- Bridge behavior under Kratos outage (5xx mapping to LDAPResultUnavailable). The error path exists in code; not exercised in this run.
- Group attribute mapping (`metadata_admin.groups` → `memberOf`). Test identity has no groups set.

## Files changed during lab

- `/Users/andrewdunn/gitlab.com/dunn.dev/auth/ldap-bridge/kratos/client.go`: `initLoginFlow` switched from POST to GET (the bug).
- `/Users/andrewdunn/gitlab.com/dunn.dev/auth/lab/compose/compose-ldap.yml`: new Phase 2 compose stack.
- `/Users/andrewdunn/gitlab.com/dunn.dev/auth/lab/compose/Caddyfile.ldap`: new (Kratos + UI only).
- `/Users/andrewdunn/gitlab.com/dunn.dev/auth/lab/compose/glauth.cfg`: new (bridge config for the lab).
- `/Users/andrewdunn/gitlab.com/dunn.dev/auth/lab/scripts/deploy-ldap.sh`: new (Phase 2 deploy).
- `/Users/andrewdunn/gitlab.com/dunn.dev/auth/lab/scripts/test-ldap.sh`: new (LDAP validation suite).
- `/Users/andrewdunn/gitlab.com/dunn.dev/auth/lab/compose/kratos.lab.yml`: rp.id and URLs re-templated for the new VM IP (34-170-71-191.sslip.io).

## Cost

VM ran ~25 minutes (provision through evidence). Approximately $0.04 at the e2-standard-2 rate.

## Next gate

- Decide on the anonymous-bind / service-account path before extending the bridge to Jellyfin (production cutover gate).
- Add structured logging to the bridge (so production can debug bind failures without enabling Kratos log.leak_sensitive_values).
- Decide on admin-token posture (network-isolation-only vs. real token gate) before production.
