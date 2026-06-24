# 0001 — Auth substrate: Ory Kratos + Hydra

## Status

Accepted (2026-05-02). Supersedes the Authentik exploration (tried and replaced)
and the kanidm evaluation (structurally blocked, not pursued). See also
[0002](0002-custom-portal-oidc-registrar.md) (the portal architecture that
the BYO-UI requirement necessitates).

## Context

The estate needed a self-hosted identity provider capable of:

- Passkey-first login (WebAuthn rp.id bound to a registrable parent domain)
- OIDC/OAuth2 for app SSO at family scale (~6 users, ~15 apps)
- LDAP for apps that cannot do OIDC (Jellyfin, Apple TV)
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

**Other candidates** evaluated and rejected:

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

Four feasibility validations were run before committing: LDAP bridge
viability (glauth Handler interface, v2.5.0+), Astro cross-subdomain cookie
semantics, Hydra skip_consent threat model, and passkey rp.id parent-domain
enrollment. All returned GREEN or YELLOW-with-acceptable-risk. An adversarial
review caught two CRITICAL issues in the original plan (Kratos AAL is
per-flow not per-route; glauth uses Handler not Backend since v2.4) and
corrected them before any code was written.

The cost: BYO UI means the operator builds the Astro app. Four-to-five
components instead of one. Smaller homelab community than Authentik. Trades
accepted.

## Decision

Ory Kratos (identity) + Ory Hydra (OAuth2/OIDC) + a custom glauth-kratos
LDAP bridge + a custom Astro Node SSR portal. Kratos and Hydra are open-source
(Apache 2), self-hosted, single-binary services. The portal is the Hydra login,
consent, and logout provider, and the Kratos self-service UI host. The bridge
is a glauth Handler plugin (compile-time, not a runtime .so) that exposes
Kratos identities over LDAPS for apps that cannot do OIDC.

## Consequences

- The operator builds and maintains the portal UI. Ory does not provide one.
  This is a permanent maintenance surface that would not exist with an
  "batteries-included" IDP.
- Composable architecture: Kratos and Hydra upgrades are independent. Breaking
  changes in either must be tracked separately.
- The LDAP bridge (kratos-ldap) is a separate repo and a separate released
  image. It is not upstreamed to glauth as of v0.3.0; it is a contribution
  candidate but not guaranteed.
- Ory's self-hosted edition is fully featured for this shape. If Ory ever
  gates critical features behind Ory Network (their SaaS), this decision would
  need revisiting. The Apache-2 license limits that risk.
- Adopters of Othala inherit the Ory dependency. They need to run Kratos,
  Hydra, and Postgres. That is the floor; the portal and bridge are on top.

## Alternatives considered

See Context above. In priority order of how seriously they were evaluated:

- **kanidm** -- closest to the ideal security posture; structurally blocked on
  AI-tooling ban and BYO-UI closure.
- **Authentik** -- was the starting point; replaced due to runtime complexity
  and deployment-shape mismatch.
- **Zitadel** -- multi-container architecture mismatch; CVE cadence concern.
- **Authelia, Hanko, voidauth, Pocket-ID** -- capability gaps (no LDAP server,
  no full IDP scope) or single-maintainer bus-factor.
