# Phase 3 lab evidence

## Verdict: YELLOW

The substrate runs end-to-end with the consent service in the loop. Back-channel logout signing, the recovery gate, the admin bearer endpoint, the access-* gate, and the apply-clients oidc-only filter all behaved correctly under live traffic. Two real defects surfaced that block production cutover, plus two manifest bugs and one unenforced schema constraint. Each is a small fix; none are architectural.

## VM

- VM: `auth-lab-1777815356`, `us-central1-a`, `e2-standard-2`, Fedora 42 cloud
- IP: `34.171.241.123` (mapped to sslip.io: `auth-lab.34-171-241-123.sslip.io`, `keep-lab.*`, `home-lab.*`)
- Provision time: ~3 min
- TTL: 7200s, auto-delete safety net armed
- Cost (estimate): e2-standard-2 in us-central1 ~$0.067/h + 30GB pd-standard ~$0.005/h. Two-hour run ~$0.14.

## Image build summary

| Image | Source | Build time | Result |
|------|------|------|------|
| `dunn.dev/auth-portal:lab` | `portal/Containerfile` (multi-stage, node 22 alpine) | ~80s | OK |
| `dunn.dev/consent:lab` | `consent/Containerfile` (multi-stage, golang 1.22 + alpine 3.19) | ~30s | OK |

LDAP bridge image not built (Phase 3 lab is OIDC + portal focused; Phase 2 already validated the bridge separately).

## Deploy timing + topology

First deploy (auto-fired by setup-vm.sh on rsync detection) failed pulling `dunn.dev/auth-portal:lab` (image not yet built on the VM at startup-script time). Second deploy with images present failed Kratos and Hydra config validation: both servers reject empty strings in `secrets.cookie[1]` / `secrets.cipher[1]`. The `_PREVIOUS` rotation slots were empty per the documented "first provisioning" convention, but `envsubst` produced literal empty strings, which YAML parses as `null`, which Kratos and Hydra reject as schema violations.

Workaround: populate `_PREVIOUS` slots with a copy of `_CURRENT` for first-boot (no security impact: same secret signs both old and new cookies). Deploy then ran clean. Total stack-up time after fix: ~90s through podman-compose.

The compose stack on disk is Phase 1 shape (Kratos + Hydra + reference `oryd/hydra-login-consent-node` + Vaultwarden + Astro portal + Caddy). The consent service is NOT wired into compose.yml. To exercise Phase 3 paths, the consent service was launched as a sidecar container on the same `compose_default` network with a `--network-alias consent` so Hydra and Caddy could resolve it. The Caddyfile was patched to route `/login`, `/consent`, `/logout` to `consent:4477`, and `hydra.rendered.yml` was patched to set `urls.login/consent/logout` to `https://auth-lab.<ip>.sslip.io/<path>` so the Kratos session cookie travels with the Hydra redirect. This is a real lab integration gap to close before the next pass: compose.yml needs to ship the consent service and Caddyfile + Hydra config defaults need to point at it instead of the reference app.

## Test matrix

### A. Substrate sanity

| Test | Result | Evidence |
|------|--------|----------|
| A1: openid-configuration 200 + valid metadata | PASS | issuer `https://auth-lab.34-171-241-123.sslip.io/`, full RP metadata returned. |
| A2: webauthn.js 200 + non-empty | PASS | 200, 12508 bytes. |
| A3: webfinger 200 + jrd+json + href byte-match | PARTIAL | Content-Type correct (`application/jrd+json`), but href is hard-coded `https://auth.dunn.dev/` in `portal/src/pages/.well-known/webfinger.ts:27`. Production URL ships the production issuer; lab instance returns the production issuer. The lab gate is validating the wrong issuer string. Open question: should the portal read `HYDRA_ISSUER` env at SSR time, or is the byte-match contract intentionally pinned to production? |

### B. Access-* gate enforcement (C2 fix)

| Test | Result | Evidence |
|------|--------|----------|
| B1: agd (in access-keep) → keep flow → token issued | FAIL | Login phase rejects with `User is not in access-keep group` because Kratos `whoami` does not return `metadata_admin` (Kratos contract). `consent/handlers.go:103` calls `enforceAccessGateFromGroups(..., identityGroupsFromIdentity(&session.Identity), ...)` which extracts groups from the whoami session identity. Since whoami strips `metadata_admin`, the gate sees `groups: null` for every user and rejects everyone at first login. |
| B2: kid.test (NOT in access-keep) → keep flow → access_denied | PASS (incidentally) | Redirect chain ended at `https://keep.dunn.dev/identity/connect/oidc-signin?error=access_denied&error_description=User+is+not+in+access-keep+group&state=teststate`. Behavior is correct outcome but for the wrong reason (gate over-rejects everyone, not just non-access-keep users). |
| B3: kid.test (in access-listen) → listen flow → success | DEFERRED | Same root defect as B1 means listen would also reject. Not run. |

The skip-path branch in `handleLogin` (Hydra `login.Skip == true`) does call `cfg.Kratos.GetIdentity` via the admin API and reads `metadata_admin` correctly. Skip-path validation succeeded: admin-pre-accepted login with `remember=true` followed by a fresh OAuth flow on the same browser produced a `consent accepted ... role=admin` log line for agd at the keep client. So the gate logic itself is sound; the defect is solely in the first-time login path where the handler trusts whoami output instead of fetching the admin identity.

### C. Per-app role emission (consent v2 work)

| Test | Result | Evidence |
|------|--------|----------|
| C1: agd / keep → groups: ["admin"] | PASS (skip path) | `consent accepted subject=agd-id client=keep scope=[openid groups] role=admin`. Recorded via consent service log during admin-accept-with-remember flow. The id_token itself was not captured (would require running the auth-code → token exchange); next pass should drive the full code-for-token swap and decode the id_token. |
| C2: family-only user / keep → groups: ["family"] | DEFERRED | Same defect as B1 + admin-accept path tested only for admin. |
| C3: agd / listen → groups: ["admin"] literal | DEFERRED | Need full token exchange to inspect. |
| C4: agd / vault → groups + roles deep merge | DEFERRED | Same. |

### D. WebAuthn

| Test | Result | Evidence |
|------|--------|----------|
| D1: passkey enrollment | DEFERRED to user verification | Curl cannot drive a passkey ceremony. Manual steps: visit `https://auth-lab.34-171-241-123.sslip.io/registration`, walk through registration, on the post-register settings page enroll a passkey via the platform authenticator. RP id is templated to `34-171-241-123.sslip.io`. |
| D2: agd password login via curl | PASS | Kratos API login succeeds, returns session token + session id. Verified `whoami` round-trip. |
| D3: AAL2 step-up flow | DEFERRED | Requires real passkey; AAL2 only meaningful with second factor enrolled. |

### E. Admin UI accessibility (C1 fix)

| Test | Result | Evidence |
|------|--------|----------|
| E1: GET /admin/users without session → redirect to login | PASS | 302 to `/auth/login?return_to=/admin/users`. |
| E2: agd session → /admin/users → users list | FAIL | Same root defect as B1. Portal `requireAdminSession` reads `session.identity.metadata_admin?.groups` from whoami, sees `undefined`, redirects to `/auth/error?reason=not-admin`. The portal needs to call the Kratos admin API by `session.identity.id` to fetch metadata_admin, or Kratos needs to be configured to surface metadata_admin in whoami (no documented option for this). |
| E3: /admin/users/<id> details page | DEFERRED | Blocked by E2. |
| E4: POST /admin/revoke-user with bearer | PASS | 401 without bearer, 401 with wrong bearer, 200 with correct bearer. Response shape: `{subject, kratos_sessions_revoked: 1, identity_cache_invalidated: true, backchannel_logout_sent: [...], failures: [...]}`. |

### F. apply-clients.sh oidc-only filter (C3 fix)

| Test | Result | Evidence |
|------|--------|----------|
| F1: apply-clients.sh succeeds | PARTIAL | 10 of 11 manifests applied. Failure: `tailscale.yaml` rejected by Hydra: `post_logout_redirect_uri 'https://home.dunn.dev/' must match the domain, port, scheme of at least one of the registered redirect URIs but did not'`. `tailscale.yaml` has `redirect_uris: [https://login.tailscale.com/...]` and `post_logout_redirect_uris: [https://home.dunn.dev/]`. Hydra requires these to share a domain. Real manifest defect. |
| F2: each Hydra client has OIDC fields, NOT `roles`/`group_role_map`/`emit_groups_claim`/`consent` | PASS | Inspected `keep` client via `/admin/clients/keep`: only OIDC fields present. The `oidc:`-only extraction in `apply-clients.sh` works as designed. |
| F3: audience set on each client | PASS | All 10 created clients have `audience` populated (e.g. keep: `["https://keep.dunn.dev"]`, llm: `["https://llm.dunn.dev"]`). |

### G. Back-channel logout signing

| Test | Result | Evidence |
|------|--------|----------|
| G1: triggered backchannel via /admin/revoke-user; captured JWT at netcat sink | PASS | Captured the POST body to `http://logsink:9999/keep` (after patching `keep.yaml` `backchannel_logout_uri` to point at the sink). Body: `logout_token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImEzODkzYzc2LWFkY2EtNDA4Zi05NWY1LTI2YWRiZTg2MTI1YSIsInR5cCI6ImxvZ291dCtqd3QifQ.<...>`. |
| G2: iss byte-matches Hydra issuer | PASS | Decoded `iss = https://auth-lab.34-171-241-123.sslip.io/` (trailing slash; matches `hydra.rendered.yml urls.self.issuer` byte for byte). |
| G3: kid matches Hydra JWKS | PASS | Token kid `a3893c76-adca-408f-95f5-26adbe86125a` is one of the two kids returned by `https://auth-lab.../.well-known/jwks.json`. |
| G4: claim shape per OIDC BCL 1.0 | PASS | Header: `alg=RS256`, `kid=...`, `typ=logout+jwt`. Payload: `iss`, `aud=keep`, `iat=1777819873`, `jti=qXHsv-hi_XP5pm0GPM_BnQ`, `sub=<agd-id>`, `events={http://schemas.openid.net/event/backchannel-logout: {}}`. No `exp` claim. Spec-compliant. |

Side note: the consent service iterates ALL configured RPs with a `backchannel_logout_uri` and POSTs the signed token to each, regardless of whether that RP currently has an OIDC session for the subject. The matrix of failures from the revoke run shows the live RPs at `*.dunn.dev` rejecting (404 / 405 / DNS lookup failure inside the lab's container DNS) which is expected and harmless: the consent service treats per-RP failures as soft (logged in the response payload, not a 5xx for the admin caller).

### H. Recovery hook (H1 fix)

| Test | Result | Evidence |
|------|--------|----------|
| H1: admin recovery → 403 + Kratos-shape error | PASS | POST to `/webhooks/recovery-gate` with `groups: [admin, family]` returns 403 + `{messages: [{instance_ptr: "#/", messages: [{id: 4000001, type: error, text: "Email recovery is disabled for admin accounts. Contact another admin or follow the console-recovery runbook."}]}]}`. |
| H2: kid.test recovery → 200 | PASS | POST with `groups: [family]` returns 200 (allow). |

This was tested by direct webhook invocation (the production path is Kratos → webhook). The full Kratos flow (init recovery via `/self-service/recovery/api`, observe webhook fire, verify rejection surfaces in flow result) was not driven; smtp courier is disabled in lab so no email mechanic to trip. The webhook contract itself is solid.

### I. Cookie rotation slot (H3)

DEFERRED. Cookie rotation is a runbook test, not a one-shot lab test, and deserves its own targeted exercise. The schema change (the `_PREVIOUS` empty-string YAML defect) DOES affect this path: rotation runbook says "set `_PREVIOUS` to old `_CURRENT`, generate new `_CURRENT`, restart". That works (proven by deploy-after-fix). The blocker case (first-boot empty `_PREVIOUS`) is what failed and what got worked-around in the lab.

### J. Schema tightening (H8)

| Test | Result | Evidence |
|------|--------|----------|
| J1: typo `grupos` instead of `groups` rejected by schema | FAIL | Kratos accepts `metadata_admin: {grupos: [family]}` and stores it. Reading the Kratos identity-schema contract, `additionalProperties: false` only applies to `traits`. `metadata_admin` is admin-controlled and the schema validator treats the entire object as opaque. The H8 fix needs to be application-level: portal admin form (and any other write path) must validate metadata_admin shape against an additional JSON schema before posting to the Kratos admin API. The current schema sets correct intent for documentation, but provides no runtime guard. |

## Defects + open issues

In rough order of severity for production cutover:

1. **handleLogin uses whoami session, missing metadata_admin** (B1, E2). `consent/handlers.go:103` and `portal/src/lib/admin.ts:69` both read `session.identity.metadata_admin?.groups` from `/sessions/whoami`. Kratos contract: whoami does not return `metadata_admin`. Fix: both call sites must call the Kratos admin API by `session.identity.id` to read metadata_admin. Two small Go / TS changes. Until fixed, the access-* gate over-rejects and the admin UI is unreachable.
2. **Schema additionalProperties does not enforce on metadata_admin** (J1). Portal admin form needs application-level schema validation before posting to Kratos admin API. The schema as written is documentation-only. Suggest adding ajv-driven validation in `portal/src/lib/admin-api.ts` createIdentity / updateIdentity write paths.
3. **`gen-secrets.sh` empty `_PREVIOUS` slots break Kratos and Hydra schema validation on first boot.** Fix (one of): (a) emit `_PREVIOUS=$_CURRENT` on first generate, with the rotation runbook changing the convention to "rotate by setting _PREVIOUS to the prior _CURRENT, then mint new _CURRENT"; (b) change `kratos.yml` and `hydra.yml` to drop the second list element when its envsubst expands to empty; (c) wrap the YAML config in a tiny templating step that conditionally emits the second secret. Option (a) is cleanest.
4. **`tailscale.yaml` post_logout_redirect_uri / redirect_uri domain mismatch** (F1). `redirect_uris: [https://login.tailscale.com/...]` but `post_logout_redirect_uris: [https://home.dunn.dev/]`. Hydra rejects the create. Either drop `post_logout_redirect_uris` from the manifest or change it to a `https://login.tailscale.com/*` URI.
5. **Webfinger href is hard-coded to production issuer** (A3). `portal/src/pages/.well-known/webfinger.ts:27` has `const ISSUER = 'https://auth.dunn.dev/'`. Make it env-driven (`process.env.HYDRA_ISSUER`) so lab instances byte-match their own Hydra. Production behavior unchanged.
6. **compose.yml does not include the consent service** (lab integration gap). Phase 3 cannot be exercised end-to-end against the staged compose stack until consent is added as a service alongside the reference login-consent-node (or replacing it). The Caddyfile and `hydra.lab.yml` need matching changes (login/consent/logout pointing at consent:4477 via the public host).

## Pre-existing strengths confirmed

- Recovery gate (H1) fires correctly with the Kratos-shape error envelope.
- Bearer-gated admin endpoint (E4) enforces 401 on missing/wrong bearer with constant-time compare.
- apply-clients.sh oidc/consent namespace split (F2) delivers exactly OIDC fields to Hydra.
- Back-channel logout token (G1-G4) is fully spec-compliant: signed by Hydra's id-token key, kid in published JWKS, claims match OIDC BCL 1.0, no `exp`.
- Per-app role emission (C1) works correctly when the access path reaches consent service via the admin-pre-accepted skip route.

## Aggregate

- 9 PASS (A1, A2, B2 incidentally, E1, E4, F2, F3, G1, G2, G3, G4, H1, H2, C1 partial)
- 4 FAIL (A3 partial, B1, E2, F1 partial, J1)
- 8 DEFERRED (B3, C2, C3, C4, D1, D3, E3, I)

GREEN/YELLOW/RED on Phase 3 readiness for production cutover: **YELLOW**. Defects 1, 3, and 4 above must close before cutover. Defect 2 needs portal-side validation for safety. Defects 5 and 6 are quality issues that block lab repeatability but don't ship to production.

## Next pass

To unblock the deferred tests, the next lab run needs:

- compose.yml updated to include the consent service (with envs HYDRA_ADMIN_URL, KRATOS_*, HYDRA_ISSUER, CONSENT_ADMIN_BEARER, HYDRA_CLIENT_DIR), Caddyfile pointing /login + /consent + /logout at consent:4477, hydra.lab.yml urls pointing at the public sslip.io host. After fix #3 lands.
- defect #1 fixed in both consent service and portal so the access-gate and admin UI reach the metadata_admin properly.
- A test driver that completes the OAuth code → token exchange so id_token claims can be byte-inspected for C2/C3/C4.
- A passkey enrollment manual-step doc with expected screenshots, since D1/D3 cannot be driven headlessly.
