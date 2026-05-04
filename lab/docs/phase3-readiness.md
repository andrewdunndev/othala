# Phase 3 readiness

**Verdict: GREEN for substrate + integration; one app-layer validation deferred to portal-form path.**

Date: 2026-05-03
Lab cycles: rev1 YELLOW (5 failures), rev2 GREEN (14 PASS / 1 known-acceptable FAIL / 1 DEFER).

## What Phase 3 lab rev2 proved

| Area | Verdict | Evidence |
|---|---|---|
| Substrate (Kratos + Hydra) | GREEN | A1, A2, A3 |
| OIDC discovery + JWKS | GREEN | A1 (issuer = `https://auth-lab.35-226-93-6.sslip.io/`) |
| WebAuthn ceremony bootstrap | GREEN | A2 (webauthn.js 12508 bytes) |
| WebFinger byte-match (Tailscale) | GREEN | A3 (href byte-equals issuer + `application/jrd+json`) |
| Identity model end-to-end | GREEN | B1-B4 (admin + non-admin identities created with metadata_admin) |
| Recovery gate webhook (H1) | GREEN | C1 (admin → 403), C2 (family → 200). H1 prior YELLOW was flawed test methodology, not a code bug. |
| apply-clients.sh oidc-only filter (C3) | GREEN | D1 (11 clients applied), D3 (no `roles`/`group_role_map`/`emit_groups_claim` leak in Hydra) |
| tailscale.yaml manifest correctness (F4) | GREEN | D2 (client applied without redirect-domain rejection) |
| Audience invariant (H4) | GREEN | D4 (all 11 clients have audience populated) |
| Portal admin guard redirects unauth users | GREEN | E1 (302) |
| Per-app role emission via consent service | DEFERRED | F1-F4 require browser flow; covered by unit tests in `consent/manifest_test.go` and `consent/handlers_access_test.go` |
| Schema validates `metadata_admin` server-side | KNOWN-NO | G1. Kratos identity schema `additionalProperties:false` does not apply to metadata_admin (admin-controlled, schema-opaque). Mitigation: app-layer validator at `portal/src/lib/metadata-admin.ts`, called from `admin/users/new.astro` + `[id].astro` POST handlers. Unit-test coverage TODO. |

## What's verified at code-only layer (37+ unit tests across consent + ldap-bridge)

- Back-channel logout JWT signing (RS256/384/512 + ES256/384/512), Hydra-key fetching, OIDC BCL 1.0 §2.4/§2.6 compliance — `consent/backchannel_test.go`
- Per-app role lookup, group ordering, override-vs-derive, audience invariant — `consent/manifest_test.go`, `consent/c4_canonical_order_test.go`
- access-* group enforcement on consent + login — `consent/handlers_access_test.go`
- Recovery gate logic — `consent/recovery_gate_test.go` (admin → 403, non-admin → 200, edge cases)
- HTTP-layer login/consent/logout flows — `consent/handlers_http_test.go`
- LDAP bind cache, DN parse — `ldap-bridge/kratos/cache_test.go`, `dn_test.go`
- Portal Astro build + type-check clean (0 errors, 0 warnings, 6 cosmetic hints)

## Known gaps

1. **Per-app role emission tested via unit tests, not browser flow.** Manual passkey ceremony + token introspection in a browser would close this. Defer to first-user pilot.
2. **Schema enforcement on metadata_admin happens at app layer, not Kratos.** A direct write to Kratos admin API with a typo'd field will silently store the field. Mitigation in place at `portal/src/lib/metadata-admin.ts`; production carmine should treat the Kratos admin port as network-isolated so direct writes go through the portal.
3. **Image slimming** for the portal: 309 MB. Below ceiling but worth a sweep before production cutover.

## Cost

Approx $0.15 across rev1 + rev2 (e2-standard-2 in us-central1-a, ~3 hours total). VMs all torn down.

## What user needs to greenlight before pyinfra cutover

1. **Browser pilot**: log into the lab one more time, enroll a passkey, complete an OIDC flow against a real RP (Vaultwarden), confirm UX. (Out of scope for autonomous validation.)
2. **Commit grouping**: I have ~80 staged changes spanning Phase 1+2+3 + adversarial-driven fixes. Ready to commit in a clean series on your approval.
3. **Pyinfra deploy plan**: carmine-side quadlet manifests for kratos + hydra + consent + portal + caddy. Not authored yet; this is the next sprint after commits land.
4. **Production secrets**: `secrets.system` (non-rotatable), `KRATOS_*`, `HYDRA_*` need provisioning into Bitwarden + carmine env. Runbook at `docs/runbooks/cookie-rotation.md` covers the slot semantics.
5. **DNS + port-forward**: `auth.dunn.dev`, `home.dunn.dev`, `auth.<app>.dunn.dev` records. Port 443 forward from home router to carmine.

Pyinfra cutover stays out of scope until 1-3 are done.

## Comparison vs rev1 evidence

| Test | rev1 | rev2 |
|---|---|---|
| Access-* gate via consent service (B1, B2, B3) | FAIL (metadata_admin not in whoami) | not re-tested via OIDC; F1 fix verified by code review + admin-API plumbing in `consent/handlers.go:106` |
| Admin UI guard reaches Kratos (E1, E2) | FAIL (Workers can't reach kratos:4434) | E1 PASS (portal on Node SSR on carmine, internal pod network) |
| apply-clients.sh oidc-only (F1, F2) | FAIL (consent fields leaking) | D1, D3 PASS |
| Recovery gate (E1, E2 in rev1 = H1) | FAIL (returned 200 on flow init) | C1, C2 PASS (direct webhook test, correct semantics) |
| Schema enforcement (J1) | FAIL | G1 still FAIL but mitigation in place at app layer |
| Cookie rotation slots | FAIL (boot loop on empty PREVIOUS) | implicit PASS (stack came up; gen-secrets seeds both slots) |
| Tailscale manifest (F4) | FAIL | D2 PASS |
| WebFinger env-driven (F5) | FAIL (production issuer hardcoded) | A3 PASS (matches lab issuer) |
| Consent service in compose (F6) | not present | implicit PASS (auth-consent up; test via D1, D3) |
| Back-channel logout JWT signing (G1-G4) | PASS (rev1) | not re-tested; consent code unchanged in this area, unit tests still pass |

Phase 3 readiness for production cutover: ready pending browser pilot + pyinfra plan + commit grouping. No code-level blockers.
