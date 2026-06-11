# Security Policy

Othala is an authentication substrate — it issues the tokens and gates the
access that everything downstream of it trusts. A flaw here is a flaw in the
front door. Reports are taken seriously and triaged ahead of feature work.

## Reporting a vulnerability

**Do not open a public issue or merge request for a suspected vulnerability.**
A public report tells everyone watching the repository how to exploit the
problem before there is a fix.

Report privately through one of these channels:

- **Email** — `andrew@dunn.dev`. Use the subject prefix `[othala-security]`.
  If you want to encrypt the report, say so in a first contact email and a key
  will be exchanged.
- **GitLab confidential issue** — open an issue at
  <https://gitlab.com/dunn.dev/othala/-/issues> and tick **"This issue is
  confidential"** before submitting. Confidential issues are visible only to
  project members.

Please include enough to reproduce:

- the affected component (`portal/`, the `kratos/` or `hydra/` config, the
  `e2e/` harness, or `gitlab.com/dunn.dev/kratos-ldap` for the LDAP bridge)
  and version or commit,
- a description of the impact (what an attacker gains — e.g. access-gate
  bypass, token-claim injection, admin-port exposure, LDAP DN escape),
- concrete reproduction steps or a proof-of-concept, and
- any deployment specifics that matter (reverse proxy, OIDC client config,
  manifest set).

If a finding is in **upstream Ory Kratos or Hydra** rather than in Othala's own
glue, report it to the Ory project (<https://www.ory.sh/docs/ecosystem/security>)
— but a heads-up here is welcome so the affected version can be pinned or
mitigated downstream.

## What to expect

This is a small, single-maintainer open-source project, not a vendor with a
24/7 security desk. Best-effort timelines:

- **Acknowledgement** of your report within **3 business days**.
- **Initial assessment** (severity, whether it reproduces, intended fix path)
  within **10 business days**.
- **Coordinated disclosure**: a fix is prepared privately, released, and only
  then is the issue made public, crediting you unless you ask otherwise.
  Please hold public disclosure until a fixed release is available, or for
  90 days, whichever comes first.

There is no paid bug-bounty program. Credit in the release notes and the fixing
commit is offered for valid reports.

## Supported versions

Fixes land on `main` and ship in a new tagged release. Only the **latest
released minor** receives security fixes; older tags are not backported. Run a
current release.

| Version        | Supported            |
| -------------- | -------------------- |
| latest `0.x`   | ✅ security fixes     |
| older `0.x`    | ❌ upgrade to latest  |

Othala is pre-1.0: minor versions can carry behavioral changes alongside
security fixes. The intended deploy shape and upgrade-durability contract are
documented in `docs/golden-path.md`; the canonical upgrade path is to pull the
new image tag and re-run the `e2e/` harness against it.

## Scope and posture

What this project treats as in-scope security surface:

- the **fail-closed access gate** (`portal/src/lib/gate.ts`, `access.ts`) —
  membership in `access-<clientId>` **and** active Kratos state; any path that
  grants access without both is a vulnerability,
- the **`OTHALA_ADMIN_IDS` allowlist** as the sole admin authority —
  identity-group membership is display metadata, never an authorization gate,
- the **loopback-only admin listener** (`:4431`) — privileged routes
  (`/admin/*`) must never resolve on the public mux (`:8080`),
- the **id_token claims builder** (`claims.ts`) — per-app role/claim mapping
  must not leak claims or roles across apps,
- the **manifest loader/validator** (`manifests.ts`) — it fails closed on a bad
  manifest set (duplicate `client_id`, audience/redirect mismatch, undeclared
  role, etc.) and keeps the prior good state,
- the **LDAP bridge** (`gitlab.com/dunn.dev/kratos-ldap`) — BIND/SEARCH
  handling, DN escaping, and the Kratos admin-token boundary,
- **secret handling** — the project holds no OAuth signing key at rest
  (back-channel logout is Hydra-signed); report any path that persists or
  exposes a secret it shouldn't,
- **application-layer abuse resistance** — the bundled reverse-proxy
  `rate_limit` on the self-service flows (email-code / recovery / verification /
  password) and a bound on concurrent password-hash work ship **with the
  install**, not as an edge add-on. A path that lets unauthenticated volume
  flood a family inbox, brute-force a credential, or exhaust host memory via
  argon2 is in scope. A Cloudflare/edge WAF is optional defence-in-depth, never
  the load-bearing control — Othala must be safe to self-host without one,
- **browser hardening of the auth UI** — anti-clickjacking (`frame-ancestors` /
  `X-Frame-Options`) on the login and consent pages, a Content-Security-Policy,
  `nosniff`, a tight `Referrer-Policy`, and self-hosted assets (no third-party
  CDN that could leak `flow` / `consent_challenge` identifiers via `Referer`);
  a missing, weak, or bypassable header here is in scope.

Out of scope:

- vulnerabilities in third-party dependencies with no Othala-specific exploit
  path (report those upstream; Renovate keeps deps current here),
- findings that require an already-compromised host, the operator's secrets, or
  physical/console access (the recovery break-glass is console-only **by
  design** — see `docs/STATUS.md` "Locked decisions"),
- the `e2e/` test domain (`othala.test`, an RFC 6761 reserved name) and its
  throwaway per-run secrets,
- volumetric / network-layer (L3–L4) DDoS that requires upstream capacity to
  absorb — that remains a host/edge concern. **Application-layer** abuse
  (email-code/recovery flooding, credential brute-force, password-hash CPU/memory
  exhaustion) is **in scope** and ships mitigated by the bundled Caddy `rate_limit`
  plus the Ory flow config; see `docs/hardening.md`. It is not delegated to a CDN.

Adversarial security review and its remediation are tracked in
`docs/security-review-2026-05-04.md`; the fuzz suites
(`portal/scripts/*.fuzz.test.mjs`) and the `e2e/` harness are part of the
standing guard against regressions.
