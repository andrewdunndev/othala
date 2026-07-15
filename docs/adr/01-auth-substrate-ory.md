# 01 — Auth substrate: Ory Kratos + Hydra

## Status

Accepted (2026-05-02); amended 2026-06-29 — the LDAP bridge this ADR
originally shipped as part of the substrate was never deployed and has been
retired (see the amendment note in Context and Consequences).

Supersedes the Authentik exploration (tried and replaced) and the kanidm
evaluation (structurally blocked, not pursued). See also
[02](02-custom-portal-oidc-registrar.md) (the portal architecture the BYO-UI
requirement necessitates), [05](05-passkey-first-auth.md) (the passkey-first
enrollment this substrate carries), and [10](10-first-party-skip-consent.md)
(the Hydra skip_consent posture validated below). Retiring the LDAP server
itself is an instance-level decision, outside this record.

## Context

The estate needed a self-hosted identity provider capable of:

- Passkey-first login (WebAuthn rp.id bound to a registrable parent domain)
- OIDC/OAuth2 for app SSO at family scale (~6 users, ~15 apps)
- An auth path for apps that cannot do interactive OIDC (native clients:
  Jellyfin on Apple TV, Infuse). The original plan answered this with a
  standalone LDAP server; see the amendment note below.
- A fully custom UI with no third-party SSO challenges in the auth path
- Long-term self-hosted viability -- no SaaS dependency for the auth flow

The decision was non-trivial. Six substrates were evaluated before landing here.

**Authentik** was the starting point. The original auth stack used Authentik.
It was replaced. The reasons: runtime complexity (multiple Python workers,
Redis, Celery), a Kubernetes-first architecture that does not map cleanly to a
rootless-quadlet homelab, and a CVE cadence that required more active patching
attention than the operator wanted to carry long-term. Authentik is a capable
product; the fit was wrong for this deployment shape.

**kanidm** was evaluated next as the closest match to the security posture
wanted. Two structural blockers ruled it out:

1. The kanidm AGENTS.md contains an explicit AI/LLM ban (an Anthropic refusal
   trigger). This is not a knock on the project; it is a deployment constraint:
   the operator uses AI-assisted tooling for maintenance and cannot use a
   project that prohibits it in its contribution guidelines.
2. Forward-auth and BYO-UI are explicitly closed by kanidm's maintainers.
   The operator needed full control of the login UI (brand, passkey-first UX,
   ᛞ→ᛟ rune greeting). kanidm does not offer that path.
   Additional note: the project has a single primary maintainer, which is a
   bus-factor consideration for critical auth infrastructure.

**Other candidates** evaluated and rejected (LDAP-server-mode was a hard
requirement at evaluation time, which is why several were disqualified on it —
that requirement was later dropped; see the amendment note):

- Authelia: no LDAP server mode; lldap as a companion inverts the dependency
  (lldap would become source of truth for the estate when its only consumer is
  Jellyfin).
- Hanko: a passkey UX layer, not a full IDP. Does not emit OIDC tokens; does
  not serve LDAP.
- voidauth: single maintainer; no LDAP server, no WebFinger, no
  client_credentials grant.
- Pocket-ID: consumes LDAP, does not serve it. Same gap as Authelia and voidauth.
- Zitadel: multi-container architecture (more moving parts than Ory); concerning
  CVE cadence relative to the project's maturity.

**Ory's offer for this shape:** Kratos owns identity (login, registration,
recovery, settings, sessions). Hydra owns OAuth2/OIDC (authorization server,
token issuance, client management). Both are single statically-linked binaries
with a well-defined configuration surface, Apache-2 licensed, and fully featured
in the self-hosted edition. The UI is the operator's responsibility -- which is
exactly what this project needed: total control of the login experience, with
Ory handling the cryptographic and protocol-correctness guarantees underneath.

Three feasibility validations still stand behind this substrate: Astro
cross-subdomain cookie semantics, the Hydra skip_consent threat model
([10](10-first-party-skip-consent.md)), and passkey rp.id parent-domain
enrollment ([05](05-passkey-first-auth.md)) — all GREEN or
YELLOW-with-acceptable-risk. An adversarial review of the original plan caught a
CRITICAL correctness issue that still holds: Kratos AAL is enforced per-flow,
not per-route. (The original plan also evaluated a glauth LDAP-bridge shim; that
validation is now moot — see the amendment note.)

The cost: BYO UI means the operator builds the Astro app. Smaller homelab
community than Authentik. Trades accepted.

**Amendment (2026-06-29) — LDAP bridge retired, never deployed.** The original
decision (below, as first written) listed a custom `glauth`→Kratos LDAP bridge
(`kratos-ldap`) as a shipped component of the substrate, standing up an LDAPS
:636 listener so apps without an OIDC client could BIND against the same Kratos
identities. That bridge was never deployed. Its one intended consumer, Jellyfin,
turned out not to need it: browser logins go through the ZL154/JellyfinSecurity
OIDC plugin against the `cinema` Hydra client, and native/Apple TV clients
authenticate with a **Jellyfin-local password** the user sets in the app — the
estate identity never enters the native path. Other non-OIDC apps sit behind
Caddy `forward_auth` → Kratos `/sessions/whoami`. A standing LDAPS listener plus
a privileged Kratos admin BIND was pure attack surface with no remaining
consumer, and it pinned an unwanted Kratos AAL constraint (whoami forced to
`aal1`). The `kratos-ldap` code is parked in its own repo, not deleted, for a
future app that genuinely needs LDAP. That retirement is an instance-level
decision. No `dag-ldap-bridge` quadlet exists in the deployed dag service; the
substrate is Kratos + Hydra only.

## Decision

Ory Kratos (identity) + Ory Hydra (OAuth2/OIDC) + a custom Astro Node SSR
portal. Kratos and Hydra are open-source (Apache 2), self-hosted, single-binary
services. The portal is the Hydra login, consent, and logout provider, and the
Kratos self-service UI host ([02](02-custom-portal-oidc-registrar.md)). There is
no LDAP server and no LDAP bridge in the deployed substrate.

Services authenticate against this substrate one of three ways:

- **OIDC**, for clients that speak it — e.g. Jellyfin via its
  ZL154/JellyfinSecurity plugin and the `cinema` Hydra client
  (`authorization_code` + `refresh_token`, `skip_consent: true`).
- **A service-local password**, for native clients that cannot run an
  interactive OIDC redirect — Apple TV / Infuse set a Jellyfin-local password in
  the app. This is app-local, NOT LDAP, and is load-bearing (the only auth path
  those clients have), not a fallback to be simplified away.
- **Caddy `forward_auth` → Kratos `/sessions/whoami`**, for browser apps with no
  OIDC client (Navidrome, Gather, peers).

## Consequences

- The operator builds and maintains the portal UI. Ory does not provide one.
  This is a permanent maintenance surface that would not exist with a
  "batteries-included" IDP.
- Composable architecture: Kratos and Hydra upgrades are independent. Breaking
  changes in either must be tracked separately.
- **One service-auth substrate, not two.** With the LDAP bridge retired there is
  no second account store to keep in sync, no LDAPS listener to monitor, and no
  privileged BIND path forcing the Kratos AAL design to stay `aal1`. The floor
  for an adopter is Kratos + Hydra + Postgres; the portal sits on top.
- A future app that genuinely cannot speak OIDC **and** cannot sit behind
  `forward_auth` would re-open the LDAP question (the parked `kratos-ldap` repo),
  not quietly stand up an LDAP server.
- Ory's self-hosted edition is fully featured for this shape. If Ory ever gates
  critical features behind Ory Network (their SaaS), this decision would need
  revisiting. The Apache-2 license limits that risk.

## Alternatives considered

See Context above. In priority order of how seriously they were evaluated:

- **kanidm** -- closest to the ideal security posture; structurally blocked on
  AI-tooling ban and BYO-UI closure.
- **Authentik** -- was the starting point; replaced due to runtime complexity
  and deployment-shape mismatch.
- **Zitadel** -- multi-container architecture mismatch; CVE cadence concern.
- **Authelia, Hanko, voidauth, Pocket-ID** -- capability gaps (no LDAP server,
  no full IDP scope) or single-maintainer bus-factor. The LDAP-server gap was
  disqualifying at evaluation time; with LDAP later dropped from the estate
  entirely, that particular gap no longer bears — but the remaining gaps and the
  Ory rationale still favor this substrate.
