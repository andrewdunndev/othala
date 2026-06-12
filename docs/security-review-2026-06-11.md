# Security review

Date: 2026-06-11
Scope: the Anthropic CVP engagement. Two parts. (1) A fresh adversarial
re-review of the othala app surface (session/authz, OAuth2/OIDC, web, Kratos
config, edge/deploy), independent of the prior Opus-driven passes. (2) The
FIRST security audit of `kratos-ldap`, the standalone LDAP-to-Kratos bridge
(gitlab.com/dunn.dev/kratos-ldap) that legacy devices BIND against. The iac
deploy plane and an othala dependency/race/crypto-DoS second pass remain
pending (see "Pending tranches").
Reviewer: adversarial multi-agent analysis under Fable (5 lenses on othala, 3
lenses on kratos-ldap, coordinator adjudication), bias-controlled against the
prior review docs.

## Reading this document

Each finding carries an inline **Status:** line:

- **REMEDIATED** — fix landed in code; commit cited inline.
- **OPEN** — fix not yet landed; tracked for action.
- **ACCEPTED** — no code change; rationale captured.

othala fixes landed on branch `security/cvp-pass-1` (commits `4ed6595`
tranche 1, `38dee83` tranche 2), local and unpushed at time of writing.
kratos-ldap findings are all OPEN (audited this review, not yet fixed).

Counts at time of writing:
- othala: 0 CRITICAL, 1 HIGH-shaped (P1, conditional), 8 MEDIUM, the rest
  low/info — all REMEDIATED on the branch.
- kratos-ldap: 1 HIGH (conditional CRITICAL), 2 HIGH (transport + CI),
  several MEDIUM — all OPEN.

## Relationship to the prior reviews

`docs/security-review-2026-05-04.md` and `docs/security-review-2026-06-07.md`
closed at v0.2.0 / pre-v0.3.0. This review does not re-litigate their findings.
The CVP re-review was run bias-controlled (the agents did not read the prior
review docs or the uncommitted Opus audit) precisely to surface what those
passes missed. The largest miss was one of scope: the prior reviews never
covered `kratos-ldap`, a credential-handling service, and auditing it here
immediately surfaced a HIGH-shaped auth-bypass surface (KL-1).

## Summary

othala's application surface is in strong shape; the CVP fixes are hardening,
not evidence of a broken design. Two themes drove the othala remediations:
authorization that keyed on user-editable identity fields (P1), and an AAL1
session being sufficient to change credentials (P2). kratos-ldap had never been
adversarially reviewed; it has solid DN-parsing and cache-key controls but a
real empty-password-bind surface and an unenforced plaintext-to-Kratos trust
boundary.

## othala findings (REMEDIATED on `security/cvp-pass-1`)

### P1 — Admin authority keyed on the user-editable `email` trait
**Severity:** HIGH (conditional: full portal admin; gated by Kratos identifier
uniqueness, so the live window is an allowlisted address not yet provisioned as
an identity). **Status:** REMEDIATED (`4ed6595`).
The portal-admin gate read `traits.email`, which a user can change via the
self-service profile flow (which does not revoke the session). Re-anchored on
the immutable identity `id`: `OTHALA_ADMIN_SUBJECTS` renamed to
`OTHALA_ADMIN_IDS` (Kratos UUIDs); migrated `requireAdminSession`
(`portal/src/lib/admin.ts`), `shouldRefuseRecovery` (`access.ts`), the
recovery-gate verdict (`server/listen.mjs`), and the index display.

### P2 — AAL1 session could enroll/change credentials on an MFA account
**Severity:** HIGH. **Status:** REMEDIATED (`4ed6595`).
`selfservice.flows.settings.required_aal` was `aal1`; Kratos's secure default
is `highest_available`. Set to `highest_available` so a first-factor-only
session can no longer add a passkey or change the password on an account that
has a second factor. Password-only and passkey-only (AAL1) users are
unaffected; first-passkey enrollment is not blocked. `session.whoami` stays
`aal1` (LDAP bridge requirement).

### P3 — Email-code login bypassed the tier-3 mailbox control for admins
**Severity:** HIGH (chains into P2 for passkey-only admins). **Status:**
REMEDIATED (`4ed6595`).
The recovery gate refuses admin recovery, but `code` is also a passwordless
LOGIN method, so transient mailbox access yielded an admin AAL1 session
ungated. Added a `login.after.code` web_hook to a new `/admin/login-gate`
endpoint (reuses `RECOVERY_GATE_SECRET`) that refuses email-code login for
admin identities. Admins authenticate via passkey or console.

### P4 — forward-auth did not strip spoofable inbound identity headers
**Severity:** HIGH (per-app group-spoof if an app trusts the documented
header). **Status:** REMEDIATED (`4ed6595`).
The `forward-auth` snippet documented apps reading `X-Kratos-Groups`, but Caddy
only copies the identity-id from the whoami response and never strips inbound
client headers, so a logged-in user could forge `X-Kratos-Groups: admin`. Both
`forward-auth` and `admin-session` snippets now strip the inbound
`X-Kratos-*` / `X-Remote-*` / `X-Forwarded-User|Groups|Email` /
`X-Auth-Request-*` families before proxying. Guidance corrected: group
enforcement is server-side (OIDC access gate or a dedicated forward_auth
endpoint), never a passed header.

### P5 — AAL2 admin freshness silently failed open
**Severity:** MEDIUM. **Status:** REMEDIATED (`38dee83`).
The freshness gate read `session.authenticated_at`, which Kratos may omit from
whoami, and failed open when absent. Switched the primary source to
`authentication_methods[aal2].completed_at` (fallback `authenticated_at`),
extracted to a tested `isSessionFresh()` helper. Fail-open remains only as a
last resort when no timestamp is readable.

### P6 — Logout did not end Hydra SSO
**Severity:** MEDIUM. **Status:** REMEDIATED (`38dee83`).
Hydra's remembered login outlived a Kratos logout, so a re-authorize silently
re-minted tokens. `handleLogin` now re-verifies a live Kratos session whose
subject matches before honoring a `login.skip`; otherwise it forces interactive
login. `handleLogout` is also subject-bound (refuses cross-user forced logout).

### P7 — User-editable `recoveryEmail` was a persistence backdoor
**Severity:** MEDIUM. **Status:** REMEDIATED (`38dee83`).
An attacker holding a brief AAL1 session could set `recoveryEmail` and recover
back in after a password reset. Mitigated by P2 (settings now AAL2 for MFA
users), the existing lost-device runbook (Step 2b clears the trait), and a new
verification binding on `recoveryEmail` in the identity schema. The feature was
kept, not removed.

### P8 — Apex-scoped 90-day session cookie
**Severity:** MEDIUM. **Status:** REMEDIATED (`38dee83`, operator-tunable).
`session.lifespan` reduced 2160h (90d) to 720h (30d) to shrink the window in
which a compromised subdomain app can replay the apex cookie. Apex scope and
`persistent` are unchanged (required for cross-subdomain SSO). Tunable; 7-14d
is a reasonable tighter setting given passkey re-login.

### P9 — Missing HSTS, CSP weaker than documented
**Severity:** MEDIUM. **Status:** REMEDIATED (`38dee83`).
Added `Strict-Transport-Security` (2y, includeSubDomains, preload) and
`form-action 'self'` to the CSP (Kratos forms POST same-origin). A strict
`script-src`/nonce remains deferred pending WebAuthn-ceremony validation, as
documented.

### P10 — `rate_limit` depends on a Caddy module absent from the prod image
**Severity:** MEDIUM. **Status:** OPEN (cross-repo deploy gate).
`caddy/Caddyfile` uses `rate_limit`, but `dunn.dev/caddy-estate` does not build
`caddy-ratelimit`; Caddy fails to start without it. Cannot be fixed in this
repo. Strengthened to a BLOCKER note in `caddy/Caddyfile` and a pre-deploy
checklist item in `DEPLOY.md`. caddy-estate must build the module before the
dag Caddyfile deploys.

### P11 — No container hardening in the golden compose
**Severity:** MEDIUM. **Status:** REMEDIATED (`38dee83`, needs carmine
validation).
`e2e/compose.yml` is the source-of-truth deploy shape but declared no hardening.
Added `no-new-privileges`, `cap_drop: ALL`, `pids_limit` to all long-running
services; `read_only` + tmpfs to kratos/hydra/othala/caddy. postgres and mailpit
deliberately omit `read_only` pending validation. The `read_only` set needs a
live e2e run to confirm Ory/Node do not need additional writable paths.

### P12 — render-config.sh YAML-injection / truncation
**Severity:** MEDIUM. **Status:** REMEDIATED (`38dee83`).
The renderer substituted secrets into unquoted YAML scalars with only a newline
guard, so a value containing ` #` could truncate the DSN. Templates now
double-quote every `${VAR}` scalar; the renderer escapes backslash/quote,
rejects control characters, and validates the rendered YAML parses. Verified
with a password containing `"`, ` #`, and `!` round-tripping intact.

### Low / informational (all REMEDIATED on `38dee83` unless noted)

- Consent CSRF token is now action-scoped (`'consent'`); logout auto-accept is
  subject-bound.
- `/apps/[slug]` checks the session before tile existence (closes pre-auth slug
  enumeration).
- Manifest URLs run through a `safeHref()` http/https scheme allowlist.
- CSRF error body no longer reflects the raw attacker-submitted action segment.
- `code` method: explicit `max_submissions: 5` and `lifespan: 15m`
  (brute-force bound; the per-method lifespan key needs Kratos v26.2.0
  confirmation).
- recovery-gate jsonnet comments corrected to the id-based model; CI gains a
  jsonnet drift-guard job (`lint-jsonnet-hooks`).

## othala second pass (dependency / races / DoS)

A focused second pass over the lenses the first sweep ran shallow.

### DOS-1 — Rate-limit key is X-Forwarded-For-spoofable
**Severity:** HIGH. **Status:** REMEDIATED (tranche 3).
The first pass recorded the rate-limit key as authoritative ("XFF fallback
removed"). It was not: `@astrojs/node` resolves `clientAddress` from the
leftmost `X-Forwarded-For` entry, and no Caddy config stripped inbound XFF, so
an attacker prepends a fresh XFF per request and bypasses the `/api/request`
email-bomb limit. Fixed at the edge: all portal `reverse_proxy` blocks
(`caddy/Caddyfile`, `e2e/caddy.Caddyfile`) now `header_up X-Forwarded-For
{remote_host}`, overwriting any client-supplied value with the real socket peer.
Caveat: if Caddy is ever placed behind another proxy (e.g. Cloudflare), the
overwrite must move to the outermost edge or use `trusted_proxies`.

### DOS-2 — Rate-limit Map OOM-poisonable (chains with DOS-1)
**Severity:** MEDIUM. **Status:** REMEDIATED (tranche 3).
The `hits` Map in `lib/contact.ts` only swept fully-expired keys. Added a hard
cap (`HITS_MAP_MAX = 10000`): over the bound after the expiry sweep, the map
clears, bounding memory. With DOS-1 fixed the flood vector is largely closed;
this is the defense-in-depth backstop.

### DOS-3 — Public SSR POSTs accepted 1 GiB bodies
**Severity:** MEDIUM. **Status:** REMEDIATED (tranche 3).
The admin loopback port bounded bodies at 1 MB but the public SSR handler used
the adapter default of 1 GiB, so every public POST buffered up to 1 GiB before
validation. Set `bodySizeLimit: 262144` (256 KiB) on the node adapter.

### CRYPTO-1 / CRYPTO-2 — CSRF signing hardening
**Severity:** LOW. **Status:** REMEDIATED (tranche 3).
The HMAC body is dot-joined and relied on an unenforced "no field contains a
dot" invariant; `signToken` now throws if `identityId` or `action` contains a
`.`. The secret-length gate counted UTF-16 chars; it now counts UTF-8 bytes
(`Buffer.byteLength >= 32`).

### F1 — nodemailer CRLF advisories
**Severity:** MODERATE (dependency). **Status:** REMEDIATED (tranche 3).
`nodemailer` bumped 7.0.13 to ^8.0.11 (GHSA-vvjj-xcjg-gr5g, GHSA-c7w3-x93f-qmm8).
Runtime `npm audit --omit=dev` now reports 0 vulnerabilities.

### C1 / C3 / C7 — concurrency notes
**Status:** OPEN / ACCEPTED.
- C1 (MEDIUM): CSRF single-use is a process-local Map; correctness depends on
  the single-instance deploy. The intra-process check-and-consume is race-free
  (synchronous, no await). Documented in `csrf.ts`; a boot guard refusing
  multi-replica without a shared store would make the assumption load-bearing.
  OPEN (low priority; single-instance today).
- C3 (MEDIUM): the manifest/tile mtime cache has a partial-read / mtime-
  granularity TOCTOU window (up to the 30s TTL). Manifests run pre-swap
  validation + prior-cache-restore, so a torn file that fails validation cannot
  poison; the residual is a torn-but-still-valid file with looser constraints.
  Fix is operator-side: the manifest sync must write atomically (temp + rename).
  OPEN (doc/operator).
- C7 (LOW): admin identity update is read-modify-write with no optimistic
  concurrency; two admins editing the same identity is last-writer-wins. Family
  scale / single admin makes this near-zero. ACCEPTED.

Positive controls verified: runtime dependency tree healthy (no HIGH/CRITICAL;
Ory fetch SDK, DOMPurify 3.4.9, marked 18, cookie 1.1.1 all current), lockfiles
committed with `npm ci`, no committed secrets, `deepMergeClaims` prototype-
pollution-safe, all user-facing regexes linear (no ReDoS), `revokeSubject`
deactivate-before-delete ordering correct, login-skip re-verify correct.

Dependency-CI gap: CI generates an SBOM (syft) but never scans it; no `npm
audit` / CVE gate. This is the othala instance of the estate scanning gap below.

## kratos-ldap findings (OPEN — first audit, not yet remediated)

### KL-1 — Empty-password bind has no local guard
**Severity:** HIGH (CRITICAL if Kratos accepts a blank password for any
identity). **Status:** OPEN.
`kratos/handler.go` never rejects an empty password; it relies entirely on
Kratos returning 4xx. The gldap library coerces a SASL bind (any bind packet
with more than 3 children) into an empty-password simple bind before the
handler sees it. In an all-passkey estate, identities may have no password
credential at all, and Kratos's response to a password-login against a
passwordless identity is the untested edge. There is no test for a blank-
password bind. Fix: reject `bindSimplePw == ""` fail-closed before any Kratos
call, add a test, and verify Kratos's passwordless-login behavior.

### KL-2 — Plaintext `http://` outbound to Kratos
**Severity:** HIGH (by-design in-pod, but unenforced and under-documented).
**Status:** OPEN.
Every user password (login POST body) and the admin bearer token traverse the
pod network in cleartext, with no scheme guard in code. An operator pointing
`KRATOS_ADMIN_URL` at another host silently leaks the bearer cross-host. Fix:
document the in-pod cleartext assumption as a hard boundary in the security
posture, and/or enforce a loopback/Tailscale assertion or TLS on the outbound
client. Decision item: is plaintext-to-Kratos acceptable on the carmine
single-host topology.

### KL-3 — Stale-auth window and missing identity-state check
**Severity:** MEDIUM. **Status:** OPEN.
`VerifyPassword` inspects only HTTP 200, never whether the identity is `active`;
plus the 30s bind cache serves the old credential after revocation. Fix: check
identity state; consider shortening the bind-cache TTL or wiring a revocation
flush on deactivation.

### KL-4 — No LDAP listener timeouts (slowloris / FD exhaustion)
**Severity:** MEDIUM. **Status:** OPEN.
The admin HTTP server has explicit read/write/idle timeouts; the gldap LDAP/
LDAPS listeners have none. Idle or partial-bind connections hold goroutines and
sockets indefinitely. Fix: set connection timeouts and/or a max-connection cap.

### KL-5 — Unbounded bind-cache growth; whole-cache flush amplifier
**Severity:** MEDIUM. **Status:** OPEN.
The bind cache has no max size and no reaper (lazy expiry only); `FlushOne`
flushes the entire cache. Fix: cap size + add a sweep; scope flush to the
subject where feasible.

### KL-6 — Unthrottled service-account bind enables roster enumeration
**Severity:** MEDIUM. **Status:** OPEN.
Directory search is gated only by the static service-account password with no
rate limit or lockout, so it is brute-forceable over LDAP, and one success
discloses the full identity roster and group graph. Fix: add bind rate limiting
/ lockout.

### KL-7 — CI security gates are thinner than advertised
**Severity:** HIGH (supply-chain gate gap). **Status:** OPEN.
gosec runs only as a golangci-lint subset (no standalone/SARIF); there is no
container image CVE scan (no Trivy/Grype on the generated SBOM); the scheduled
fuzz job is dormant until a CI schedule is created; images/components are
tag-pinned not digest-pinned. `govulncheck`-blocks-on-tag is the one genuine
gate. This is the per-repo instance of the estate-wide scanning gap (see
"Estate scanning gap").

### kratos-ldap positive controls verified

DN parsing is fail-closed and fuzz-hardened (rejects `,=\x00\` and control /
Unicode whitespace; no injection sink into Kratos). Search authz is fail-closed.
The bind-cache key correctly includes the password and a per-process salt, so
the obvious cache-poisoning attack (wrong password hitting a positive entry) is
closed. The Argon2 semaphore correctly bounds hashing amplification. Constant-
time compares throughout. Non-root container. No `InsecureSkipVerify`, no
credential logging. Config fails closed on missing secrets.

## Estate scanning gap (drives the self-hosted scanning work)

The dunn.dev pipeline catalog has dependency-audit (govulncheck / cargo-audit /
npm-audit), SBOM (syft), and SLSA/cosign signing, but no SAST (gosec/semgrep),
no secret scanning (gitleaks), and no container/filesystem CVE scanning (Trivy/
Grype/osv-scanner) as reusable components. KL-7 is the per-repo symptom. The
remediation is catalog-level, Ultimate-independent, open-source-tool components,
consumed at a pinned catalog version (tracked separately).

## Accepted / deferred

- PKCE disabled for confidential clients (Tailscale constraint).
- Postgres `sslmode=disable` (internal step-ca PKI spike deferred per posture).
- Ory admin APIs unauthenticated (Ory network-is-the-control model; verify bind
  hosts in the segmented deploy).
- Image digest-pinning across the estate (Renovate manages tags; revisit if the
  catalog adopts digest pinning).

## Cross-repo handoffs and deploy gates

1. iac/sops: rename `OTHALA_ADMIN_SUBJECTS` to `OTHALA_ADMIN_IDS`, fill with the
   real admin identity UUID(s).
2. New required env `OTHALA_CONTACT_RECIPIENT` (no longer falls back to the
   admin allowlist, which now holds UUIDs).
3. caddy-estate must build the `caddy-ratelimit` module (P10).
4. Live-gate validation before tagging v0.3.0: Kratos boots with the
   `login.after.code` hook and `code.config.lifespan` key; `read_only` on the
   hardened services; `form-action 'self'` against a real login POST;
   `authentication_methods` field shape for P5.

## Pending tranches

- kratos-ldap fix-pass (lead with KL-1 empty-password guard; KL-2 needs the
  plaintext-to-Kratos risk-acceptance decision).
- othala second pass: dependency/CVE (real npm tree, not image tags),
  business-logic races / TOCTOU, crypto/DoS depth (CSRF nonce-store growth,
  regex DoS, unbounded reads).
- iac audit: the deploy/secrets/segmentation plane (259 files), never reviewed.
- Estate self-hosted scanning components in the pipeline catalog.
