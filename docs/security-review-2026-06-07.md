# Security review

Date: 2026-06-07
Scope: extends `docs/security-review-2026-05-04.md`; covers portal middleware
(response headers, font loading), application-layer abuse resistance, lost-device
lifecycle, supply-chain, and the deploy-plane (quadlet configs, secrets model).
Reviewer: adversarial wave analysis (4 agents × 3 waves + coordinator adjudication).

## Reading this document

Each finding carries an inline **Status:** line.
Use these tags:

- **REMEDIATED** — fix landed in code; evidence cited inline.
- **IN PROGRESS** — fix is being implemented on the named branch.
- **ACCEPTED** — no code change; rationale captured.
- **OPEN** — fix not yet landed; tracked for action.

Counts at time of writing: 0 CRITICAL, 3 HIGH, 8 MEDIUM, 0 LOW, 1 architectural
note (revisited). No findings from the prior review are re-opened; they remain
closed as recorded at v0.2.0.

## Relationship to the prior review

The `docs/security-review-2026-05-04.md` review closed at v0.2.0 with **0 OPEN**
findings (16 REMEDIATED, 1 ACCEPTED across HIGH/MEDIUM/LOW). This review extends
it. It does NOT re-litigate any of HIGH-1…4 or MEDIUM-1…7; those remain closed.

Areas the prior review explicitly called out of scope and that are now **in scope**
here:

- **Response security headers and Content-Security-Policy** — previously not
  examined; now the single biggest application-layer gap.
- **Application-layer abuse resistance** (email-bomb, credential brute-force,
  argon2 memory-DoS) — previously declared "the operator's edge concern" in
  SECURITY.md. That scoping decision is **reversed** per the Wave-3 reframe:
  Othala must be safe to self-host without a CDN or WAF; see `SECURITY.md` and
  `docs/hardening.md §1`.
- **Physical / lost-stolen-shared device** — the dominant real-world threat for a
  family. Added as an explicit tier (see threat model below).
- **Supply-chain gate** (CVE evaluation, image pinning, auto-update posture).
- **Deploy-plane** (quadlet configs, env expansion, secrets model, e2e schema
  fidelity).

## Summary

The application core is sound: CSRF tokens, admin-recovery guards, listener split,
webhook authentication, and recovery-gate fail-closed all held under adversarial
agent review — consistent with the prior review's remediation record. The gaps
this review identifies are mostly in the **surrounding deployment envelope** and
the **browser-facing hardening layer**, not the auth logic itself. The highest-risk
items are the missing security-response headers (clickjackable login page, no CSP
containment for XSS) and the lost-device eviction gap (sessions revoked, not
credentials). The deploy-plane has two probable boot bugs that will surface at
first bring-up and must be resolved before the gate.

Counts: 0 CRITICAL, 3 HIGH, 8 MEDIUM.

## Threat model

The tier model from the prior review is carried forward. One tier is added.

**Tier 1** (passive net observer / CDN): irrelevant for TLS plaintext; only
hostnames leak.

**Tier 2** (compromised app container): one of the downstream apps gets an RCE.
The attacker is on the app's pod/network but not on the auth pod's internal
network. This remains the primary attacker tier.

**Tier 3** (compromised admin mailbox): blocked at the recovery-gate webhook for
admin identities (HIGH-3 in prior review, REMEDIATED v0.1.3; unchanged).

**Tier 4** (carmine root): out of scope; game over.

**Physical / lost-stolen-shared device** (NEW — in scope for this review): A lost
or stolen family member device with an existing session, or a shared device that
isn't properly evicted. This is the **dominant real-world threat** for a family
deployment, more likely than a tier-2 container compromise. Two specific chains
emerge from this tier and are captured as HIGH findings below. The prior review
did not model this tier explicitly.

Asset value: family identity + per-app data. Worst case is a privacy breach across
the family; not financial-fraud scope.

## CRITICAL

None.

## HIGH

- **HIGH-A: No response security headers; login and consent pages are
  clickjackable.**
  - `portal/src/middleware.ts` only rebrands errors and forwards the response;
    `portal/astro.config.mjs` sets no `server.headers`. Zero security headers are
    set anywhere in the tree — no `X-Frame-Options`, no `Content-Security-Policy`,
    no `X-Content-Type-Options`, no `Referrer-Policy`, no `Permissions-Policy`, no
    `Cross-Origin-Opener-Policy` (release-plan Wave 2, "TWO HIGHEST-RISK").
  - The login page (`/auth/login`) and the Hydra consent page both render in an
    iframe from any origin without restriction. A tier-1 or tier-2 attacker can
    mount a clickjacking overlay to capture credentials or trick a family member
    into granting consent to a malicious OIDC client.
  - The absence of CSP is also the standing threat against any XSS regression: if
    a future `set:html` path over user-controlled content is introduced, the full
    browser session is in scope (no containment).
  - The `Referrer-Policy` gap compounds the font-loading finding below (HIGH-B):
    without `no-referrer`, the `flow` and `consent_challenge` query parameters on
    those pages leak in the `Referer` header on every sub-resource request.
  - Threat tier: 1 (anyone). Asset at risk: credential capture via clickjacking;
    full XSS blast radius if any future `set:html` sink is introduced.
  - Fix: add a single header block after `next()` in `portal/src/middleware.ts`:
    `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, `nosniff`,
    `Referrer-Policy: no-referrer`, `Permissions-Policy` (deny camera/mic/geo),
    `Cross-Origin-Opener-Policy: same-origin`. Follow with a nonce-based CSP once
    fonts are self-hosted. Full spec in `docs/hardening.md §2`.
  - **Status: IN PROGRESS (feat/passkey-first-login).** The header middleware
    block and self-hosted fonts are being implemented in this branch.

- **HIGH-B: Auth UI loads fonts from Google Fonts CDN.**
  - The portal currently fetches IBM Plex fonts from `fonts.googleapis.com` /
    `fonts.gstatic.com`. Two consequences: (1) every page load that triggers a CDN
    fetch carries the page `Referer` header, which includes `?flow=<uuid>` and
    `?consent_challenge=<token>` — sending those identifiers to a third-party CDN
    without consent. (2) A `default-src 'self'` CSP cannot be deployed while an
    external font CDN is in use; the CSP either allows the CDN (weakening it) or
    breaks fonts. Self-hosting is the prerequisite for HIGH-A's nonce-based CSP.
  - Threat tier: 1. Asset at risk: `flow` / `consent_challenge` token exposure to
    Google; blocks CSP deployment.
  - Fix: download IBM Plex (woff2) into `portal/public/fonts/`, update the CSS
    `@font-face` references, remove the `<link rel="preconnect">` tags pointing to
    Google. LFS posture applies for the binary font files. Full spec in
    `docs/hardening.md §2`.
  - **Status: IN PROGRESS (feat/passkey-first-login).** Self-hosting is being
    implemented in the same branch as HIGH-A.

- **HIGH-C: Lost-device eviction is incomplete; a thief can survive a revoke.**
  - `revokeSubject` (the "Force re-login" path, `consent/admin.go`) terminates
    active Kratos sessions and fans out back-channel logout to relying parties. It
    does **not** delete enrolled credentials (passkeys, TOTP, backup codes). A
    thief who obtains a brief AAL1 session — e.g. from an unlocked phone where
    email-code completes before the owner notices — can enroll their own passkey
    inside the 15-minute `privileged_session_max_age` window. That enrolled
    credential survives `revokeSubject` and a password reset. The thief calls
    `POST /self-service/login/browser` with their own passkey and logs straight
    back in. Operator's "Force re-login" buys zero durable security in this
    scenario (release-plan Wave 3, "LOST/STOLEN/SHARED DEVICE", SEV1 chain 1).
  - The correct eviction sequence is: admin audits the identity's enrolled
    credentials → deletes any credential the user does not recognise → then calls
    revokeSubject. This sequence is not documented in `docs/runbooks/admin-recovery.md`
    and the admin UI must expose per-credential deletion clearly enough that an
    operator under stress finds it.
  - Threat tier: physical (lost/stolen device). Asset at risk: persistent account
    access by the device thief despite the operator believing the account was
    revoked; worst case is the thief re-enrolls on an admin account path (if the
    owner is admin and the thief's window included AAL2).
  - Fix: update `docs/runbooks/admin-recovery.md` to make credential-audit-then-
    delete step 1 of any lost-device procedure. Confirm the admin UI credential
    chips surface passkey / TOTP / backup-code enrollments with per-credential
    delete actions (verifiable only live — W4 live-validation item 6). Add
    `p-eviction.spec.ts` to the e2e harness: enroll victim and thief passkeys,
    revokeSubject, assert thief can still authenticate, then delete thief credential,
    assert thief is locked out. Full spec in `docs/hardening.md §7`.
  - **Status: OPEN.** Runbook update is in progress (W5); credential-chip and
    delete-action live-verification is a joint-gate item.

## MEDIUM

- **MEDIUM-A: `marked` → `set:html` with no sanitiser (educationHtml).**
  - Portal renders per-app help text via `marked(educationHtml)` passed to Astro's
    `set:html`. `marked` converts Markdown to HTML and makes no attempt to sanitise.
    Today the source of `educationHtml` is operator-authored manifest files, so the
    immediate trust boundary holds; exploiting this requires either operator error
    or a compromised manifest directory. The reason this remains MEDIUM rather than
    LOW is the CSP gap in HIGH-A: with no CSP, any HTML injected here (even by
    accident) executes in the portal's full-privilege context, including the admin
    session. Once CSP is deployed it becomes LOW.
  - Threat tier: 2 (compromised manifest source or operator error). Asset at risk:
    stored-XSS in the portal; admin session if an admin page renders the content.
  - Fix: wrap the `marked()` call with DOMPurify before passing to `set:html`. One
    import, one call; zero UX change for legitimate Markdown. This also insures
    against a future widening of the trust boundary (shared manifest dir, CMS-fed
    content). Spec in `docs/hardening.md §2`.
  - **Status: IN PROGRESS (feat/passkey-first-login).** DOMPurify is being added
    alongside the header and font work.

- **MEDIUM-B: Application-layer abuse resistance bypassed in the shipped dag
  topology; intrinsic fix documented.**
  - The `caddy/Caddyfile` correctly rate-limits `/self-service/*` per
    `{remote_host}`. In the standard install (Caddy at the edge) this is the real
    client IP and works as shipped. In the dag deployment, Envoy fronts Caddy as an
    L4 SNI-passthrough proxy (`tls_inspector` + `tcp_proxy`, no TLS termination, no
    XFF injection), so every request arrives at Caddy from the Envoy loopback
    address. The `{remote_host}` key collapses to a single global bucket: 10
    requests per minute shared by the whole family. A normal usage burst can lock
    everyone out; an attacker from a different IP is not isolated from the bucket
    (release-plan Wave 1, "HEADLINE — CORRECTION").
  - Additionally, Kratos has no native account lockout and no resend cooldown on
    the email-code flow. The vectors: (a) email-bomb any family member via
    `/self-service/login|recovery|verification` with unauthenticated code requests;
    (b) password brute-force; (c) argon2id at 128 MB per attempt — concurrent
    password attempts can exhaust carmine's memory via a valid-looking load.
  - The SECURITY.md scope reversal (now in scope, not "edge concern") is landed.
    `docs/hardening.md §1` documents the intrinsic fix: the dag Envoy must speak
    PROXY protocol to Caddy, and Caddy must add `trusted_proxies` so it recovers
    the real client IP CDN-independently. A `max_conns` cap on the Kratos upstream
    is the argon2 brake. The CF WAF is optional redundancy, never the load-bearing
    control.
  - Threat tier: 1 (anyone). Asset at risk: family inbox flood, credential
    brute-force, host memory exhaustion.
  - Fix: (1) Caddy `rate_limit` key → `{http.request.header.CF-Connecting-IP}` is
    the interim dag fix (CF already proxies dunn.dev); the durable fix is
    PROXY-protocol + `trusted_proxies static` in the iac Caddyfile so the control
    is CDN-independent. (2) Add `max_conns` on the Kratos upstream. See
    `docs/hardening.md §1`.
  - **Status: OPEN.** caddy-estate `v2.11.4-1` ships `caddy-ratelimit`; the
    rate_limit block is in the dag Caddyfile (iac `fix/dag-caddy-static-assets`).
    The rate-key fix (PROXY-protocol or CF-Connecting-IP) and the max_conns cap are
    not yet applied.

- **MEDIUM-C: Admin session freshness unchecked; 90-day window on stolen admin
  browser.**
  - `requireAdminSession` (portal) checks that AAL2 is present in the current
    Kratos session, but it does not check when that AAL2 factor was last presented.
    `session.lifespan` is 90 days. A stolen admin browser with an existing AAL2
    session gives an attacker up to 90 days of full admin access.
    `docs/runbooks/cookie-rotation.md` claims "daily admin re-auth" but this is not
    implemented anywhere in the code (release-plan Wave 2, "ADMIN SESSION GAP";
    Wave 3, "Stolen ADMIN device").
  - Threat tier: physical (stolen/borrowed device). Asset at risk: full admin
    control for up to 90 days; every family identity subject to forced re-login,
    deactivation, or recovery-URL issuance.
  - Fix: add a `session.authenticator_assurance_level_at` freshness check in
    `requireAdminSession`: if the AAL2 factor was last presented more than N hours
    ago (4–8h recommended), redirect to the step-up flow. Alternatively correct the
    runbook to document that daily re-auth is a manual operator responsibility
    (lower security, but honest). Spec in `docs/hardening.md §7`.
  - **Status: OPEN.**

- **MEDIUM-D: Deploy-plane boot bug — `Environment=DSN=...${KRATOS_PG_PASS}...`
  in dag-kratos.container will likely fail to expand.**
  - `iac/services/dag/.config/.../dag-kratos.container` line 25 sets
    `Environment=DSN=postgres://kratos:${KRATOS_PG_PASS}@dag-postgres:5432/kratos`.
    systemd and Podman do **not** shell-expand `${}` syntax in `Environment=` lines
    (only `$VAR` without braces is expanded, and that too only in some contexts).
    Kratos reads a DSN env var and uses it in preference to the YAML `dsn` config
    key. If the env is set to a literal unexpanded string, Kratos attempts to
    connect with a password of `${KRATOS_PG_PASS}` and the boot fails. The Wave-2
    secrets agent called this "harmless"; coordinator verification confirmed it is
    not (release-plan Wave 2, "[MED, VERIFY] dag-kratos.container line 25").
  - The kratos.yml config already handles `${KRATOS_PG_PASS}` via Ory's native
    env interpolation; the duplicate `Environment=DSN=` line is redundant and
    harmful.
  - Threat tier: not a direct attack surface — a deploy-plane correctness bug that
    surfaces at first boot. Asset at risk: service fails to start; operator
    troubleshooting time.
  - Fix: remove the `Environment=DSN=…` line from dag-kratos.container (and any
    matching line in dag-hydra.container). The YAML config file path with sops
    injection remains correct and sufficient.
  - **Status: OPEN.** Must be resolved before the v0.3.0 gate bring-up.

- **MEDIUM-E: Cookie/cipher `_PREVIOUS` env slots injected but not read; rotation
  bounces live sessions.**
  - The dag quadlets inject env vars for both `_CURRENT` and `_PREVIOUS`
    cookie/cipher secrets. `kratos/kratos.yml` only references `${KRATOS_COOKIE_SECRET}`
    (and the cipher equivalent) — the `_PREVIOUS` slots are never read. The cookie
    rotation runbook describes a model where the previous secret is included in the
    config array so existing sessions continue to decode while newly issued ones use
    the new key. As-is, any rotation event that restarts Kratos with a new
    `_CURRENT` and the unused `_PREVIOUS` will invalidate every live session
    (release-plan Wave 2, "[MED] cookie/cipher `_PREVIOUS`").
  - Threat tier: not an attack surface; an operational correctness bug. Asset at
    risk: all family sessions invalidated on operator rotation, causing forced
    re-login for everyone.
  - Fix: Option A (matches `docs/runbooks/cookie-rotation.md`): drop the
    `_PREVIOUS` env injection; rotation prepends a second literal entry into the
    rendered YAML at rotation time. Option B: reference `${KRATOS_COOKIE_SECRET_PREVIOUS}`
    in a second array entry in `kratos.yml`. Pick one and make the runbook and
    config consistent.
  - **Status: OPEN.**

- **MEDIUM-F: Stale dag-portal quadlet — wrong image tag and ~12 missing env
  vars.**
  - `iac/services/dag/.config/.../dag-portal.container` is pinned to
    `othala:v0.1.3` (not v0.3.0) and is missing approximately 12 env vars required
    for correct operation: `OTHALA_PUBLIC_URL`, `CSRF_SECRET`, `OTHALA_APEX`,
    `OTHALA_WEBAUTHN_RP_ORIGINS`, `OTHALA_WEBAUTHN_RP_ID`, `OTHALA_ADMIN_SUBJECTS`,
    `OTHALA_ADMIN_ENDPOINT_BEARER`, `RECOVERY_GATE_SECRET`, `OTHALA_SMTP_*`,
    `MANIFEST_DIR`, `ADMIN_HOST/PORT`. The var name for the consent admin bearer
    also mismatches: the quadlet injects `CONSENT_ADMIN_BEARER` but the portal
    reads `OTHALA_ADMIN_ENDPOINT_BEARER`. As-is, the portal boots without a CSRF
    origin or a redirect base — any CSRF check or redirect will fail silently
    (release-plan Wave 1, "[HIGH/deploy-prep] dag-portal.container is STALE").
  - Threat tier: deploy-plane correctness; the missing `CSRF_SECRET` makes the
    portal's CSRF protection non-functional on first deploy until corrected.
  - Fix: regenerate dag-portal.container from the v0.3.0 env specification;
    add `EnvironmentFile` pointing to the sops-decrypted secrets file; correct
    the `OTHALA_ADMIN_ENDPOINT_BEARER` name. Gate item: verify all env vars present
    before first live boot.
  - **Status: OPEN.** This is the regenerate-from-v0.3.0 quadlet spec task;
    must be done before the joint gate.

- **MEDIUM-G: Container baseline absent; `AutoUpdate=registry` on Ory images.**
  - All dag quadlets (dag-kratos, dag-hydra, dag-portal, dag-postgres, dag-caddy)
    lack the standard hardening baseline: no `NoNewPrivileges=true`, no
    `ReadOnly=true` + `Tmpfs=`, no `DropCapability=all`. The Ory binaries and the
    Node portal app require ~zero Linux capabilities and no writable rootfs.
  - `dag-kratos.container` line 12 and `dag-portal.container` line 13 carry
    `AutoUpdate=registry`. Podman's registry auto-update pulls the latest image on
    a tag-digest change without running the e2e harness or verifying cosign
    signatures. On security-critical IdP containers, this is an auto-deploy path
    that bypasses the gate (release-plan Wave 2, "CONFIRMED CHEAP HARDENING").
  - Threat tier: 2 (supply-chain / compromised registry image). Asset at risk:
    malicious or buggy IdP image deployed silently; container escape easier without
    capability drop.
  - Fix: add the baseline three lines to every quadlet; replace `AutoUpdate=registry`
    with `Image=…@sha256:<digest>` pinning; manage bumps via Renovate + pipeline.
    Full spec in `docs/hardening.md §5`.
  - **Status: OPEN.** Gate-coordinated; should land alongside the full quadlet
    regeneration.

- **MEDIUM-H: Secrets as `type=env`; high-value secrets readable via /proc and
  `podman inspect`.**
  - All secrets (Hydra system secret, cookie/cipher secrets, SMTP credentials,
    admin bearers) are delivered as `Environment=` entries in the quadlets.
    Anything in the same user namespace can read `/proc/<pid>/environ`; `podman
    inspect` on the container also exposes them. The non-rotatable Hydra system
    secret is the most sensitive: leaking it allows an attacker to decrypt every
    OAuth2 client secret stored in the Hydra database and impersonate any OIDC
    client (release-plan Wave 2, "Secrets-as-ENV").
  - Threat tier: 2 (lateral from a co-located compromised process). Asset at risk:
    all OAuth2 client secrets decryptable; session cookie forgery; SMTP credential
    abuse.
  - Fix: move high-value secrets (Hydra system, cookie/cipher, SMTP, bearers) to
    rendered config file mounts or `Secret=…,type=mount` (tmpfs-backed). Ory reads
    secrets from its config file, so the rendered-config path is natural and
    requires no code changes. Spec in `docs/hardening.md §4`.
  - **Status: OPEN.** Gate-coordinated.

- **MEDIUM-I: No CVE evaluation gate; SBOMs generated but never assessed.**
  - The CI pipeline generates syft SBOMs per release. No pipeline step evaluates
    those SBOMs or runs any CVE scanner against the built images or code. The
    pipeline can produce and tag a release with a critical CVE present in a direct
    dependency without any gate firing (release-plan Wave 4, "SUPPLY-CHAIN: [HIGH]
    no CVE gate").
  - Separately: `ldap-bridge/go.mod` declares `go 1.22` and carries
    `golang.org/x/crypto` at approximately 18 months stale; it is not managed by
    Renovate (no `renovate.json` ARG annotation).
  - Threat tier: supply-chain. Asset at risk: known-exploited vulnerability in a
    dependency shipped to production without operator awareness.
  - Fix: add `grype`/`trivy` on the built image (`--fail-on high`) and
    `npm audit --audit-level=high` + `govulncheck ./...` on the portal and Go
    components to the CI pipeline; fail the build on unacknowledged high findings.
    Renovate-annotate the ldap-bridge `go.mod` ARG. Spec in `docs/hardening.md §6`.
  - **Status: OPEN.** Gate-coordinated; should be part of the W6 supply-chain pass.

- **MEDIUM-J: e2e `identity.schema.json` diverges from deployed
  `kratos/identity.schema.json`.**
  - `e2e/identity.schema.json` (the schema Playwright/Kratos uses in CI) has
    diverged from `kratos/identity.schema.json` (the one deployed to dag): the e2e
    copy adds `code.identifier: true` on `username` (not email), is missing
    `verification.via` and `recovery.via` on the email trait, and is missing
    `passkey.display_name` and the `recoveryEmail` trait. Recovery and passkey
    specs therefore test against a schema that does not match production.
    Regressions introduced by schema changes can pass CI and break at the gate
    (release-plan Wave 1, "[MED] e2e/identity.schema.json DRIFTS").
  - Threat tier: not a direct attack surface; a test-fidelity gap. Asset at risk:
    security-relevant e2e specs (recovery-gate, passkey enrollment, admin-gate
    blocks) validate a fiction.
  - Fix: make `e2e/identity.schema.json` a copy or symlink of
    `kratos/identity.schema.json`. Add a CI lint step: `diff` the two files; fail
    if they diverge.
  - **Status: OPEN.**

## Architectural concerns

**A1/A7 revisited — single trust domain and unauthenticated admin APIs (network
segmentation):** The prior review documented A1 and A7 (all pods share one Podman
network; Kratos admin `:4434` and Hydra admin `:4445` are unauthenticated by
design; the pod/network boundary is the wall) and accepted them as appropriate for
single-tenant homelab scale. The Wave-3 adversarial pass confirms this analysis
and adds precision: the Ory admin APIs are reachable from any container on `dag.network`
in ~3 curl calls, yielding arbitrary admin identity creation and full PII read.

This is **not a new finding** — it is the same A1/A7 accepted posture, now with
the blast-radius surface area quantified. `docs/hardening.md §3` documents the
three options (A: static-IP admin network + bound listener; B: Podman pod +
loopback-bound admin; C: keep accepted + cheap wins) and their tradeoffs. The
admin-surface gating decision is DECIDED for v0.3.0: Caddy `basic_auth` (bcrypt,
path-scoped to `/admin/*`) as Phase 1; step-ca mTLS as Phase 2. This adds an
outer factor on top of the app AAL2 + allowlist but does not resolve the
unauthenticated admin-API exposure on the flat network — that requires Option A or B.

The cheap-wins from A/B/C regardless: `sslmode=require` on Kratos/Hydra → Postgres
DSNs; TLS provisioned for the LDAP bridge before it serves real BIND; admin ports
(`4434`, `4445`, `8431`) confirmed with no `PublishPort`. Decision on Option A/B/C
is still OPEN; must be resolved before v0.3.0 tag.

## What's NOT in scope

- The prior review's HIGH-1…4 and MEDIUM-1…7: these remain closed as REMEDIATED
  or ACCEPTED at v0.2.0. Not re-opened.
- Per-app audience verification audit (A3 from prior review): deferred to Phase 4
  lab; unchanged.
- Postgres backup tooling and restore-correctness across Hydra encryption-at-rest
  (A6 from prior review): deploy-plane work stream; unchanged.
- Upstream Ory Kratos/Hydra code: Renovate tracks OSS releases; static review
  cannot confirm runtime behavior of the upstream binary. The v26.2.0 version
  check is complete (v26.2.1–16 are Ory Network/SaaS-only, not OSS-published;
  nothing to bump).
- Volumetric / network-layer (L3–L4) DDoS: host/edge concern. Application-layer
  abuse is now in scope (MEDIUM-B); the line is L3/L4.
- LDAP bridge TLS provisioning: flagged as a "cheap win" under A1/A7 and in
  `docs/hardening.md §3`; gate-coordinated. glauth cleartext LDAP carries the
  Jellyfin bind password on the pod network — keep ldap-bridge out of v0.3.0 scope
  until TLS is provisioned, or accept the pod-trust caveat explicitly.
- Dynamic / runtime behavior that requires the carmine stack: cookie rotation
  correctness, admin session freshness end-to-end, brute-force-lockout rate
  verification. These are live-validation gate items, not static-review findings.
- PKCE globally off: deliberate — `enforced_for_public_clients: true` already
  set; all clients are confidential; Tailscale exception known. Re-examine
  globally-enforce + per-client Tailscale exemption before public flip.

## Triage summary

### v0.3.0-blocking (must be resolved before the joint gate)

These require code or config changes that are straightforward and carry real
security or correctness consequences if skipped:

- **HIGH-A / HIGH-B** — Security headers + self-hosted fonts (IN PROGRESS on
  `feat/passkey-first-login`). Closes clickjacking and Referer-leak vectors.
- **MEDIUM-A** — DOMPurify on `educationHtml` (IN PROGRESS on same branch). Belt
  against XSS sink with no CSP.
- **HIGH-C** — Eviction runbook update + admin UI credential-audit live-verification
  (W5 + live-validation item 6). The most impactful family-safety gap.
- **MEDIUM-D** — Remove `Environment=DSN=…` unexpanded var from dag-kratos /
  dag-hydra quadlets. Probable boot failure; trivial fix.
- **MEDIUM-E** — Resolve `_PREVIOUS` rotation model (pick Option A or B; make
  runbook and config consistent). Prevents accidental full session invalidation on
  first rotation.
- **MEDIUM-F** — Regenerate dag-portal quadlet from v0.3.0 env spec. Missing
  `CSRF_SECRET` means CSRF protection is non-functional on first deploy.
- **MEDIUM-J** — Align `e2e/identity.schema.json` with `kratos/identity.schema.json`.
  Security-relevant specs are testing the wrong schema.

### Gate-coordinated (resolve at or before live bring-up, not a code-freeze blocker)

These are real and should land with the deploy-plane work, but don't block the
branch from being reviewed:

- **MEDIUM-B** — Rate-limit key fix (PROXY-protocol + trusted_proxies or
  CF-Connecting-IP interim). caddy-estate v2.11.4-1 ships the module; the key is
  wrong.
- **MEDIUM-C** — Admin session freshness (requireAdminSession AAL2 age check or
  corrected runbook).
- **MEDIUM-G** — Container baseline (NoNewPrivileges, ReadOnly, DropCapability) +
  replace AutoUpdate with digest pinning.
- **MEDIUM-H** — High-value secrets to file mounts.
- **MEDIUM-I** — CVE evaluation gate in CI pipeline; ldap-bridge Renovate annotation.
- A1/A7 network-seg option A/B/C decision + cheap wins (sslmode=require; LDAP TLS
  or ldap-bridge out of v0.3.0).

### Accepted / deferred

- `educationHtml` XSS blast radius will be LOW once CSP (HIGH-A) is deployed and
  DOMPurify (MEDIUM-A) is in — the risk degrades to operator-error/typo only.
- A3 (per-app aud verification): Phase 4 lab.
- A6 (postgres backup): deploy-plane work stream.
- PKCE global enforcement: pre-public-flip task.
- Account enumeration on email-code login: ACCEPTED (operator decision 2026-06-07);
  closed family, emails not secret; revisit if Ory adds `notify_unknown` for the
  login code strategy.
- Hydra hardening nits (bcrypt.cost 10→14; login_consent lifespan; CORS trim):
  low-risk, addressed opportunistically.
