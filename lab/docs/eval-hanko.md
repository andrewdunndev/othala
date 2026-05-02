# Hanko evaluation

Research date: 2026-05-02. Targeting Hanko 2.5 (released 2026-03-03).

## Summary

**RED for our use case.** Hanko is a passkey-first authentication
backend that applications embed (think "Auth0 alternative for the app
you are building"), not a federated identity provider that aggregates
multiple downstream apps. It has no OIDC IdP role, no SAML IdP role, no
LDAP server, and no forward-auth. The maintainers explicitly rejected
adding OIDC IdP capability in 2023 (PR #869) on scope and maintenance
grounds, and nothing in the 2.0 → 2.5 release stream has changed that
posture. The shape mismatch is load-bearing: even if maintenance,
security, and customizability were perfect, Hanko cannot be the thing
Vaultwarden, Grafana, GitLab, etc. talk to.

## Maintenance + sustainability

| Field | Value |
|---|---|
| Latest release | 2.5 (2026-03-03) |
| Release cadence | Roughly monthly minor/patch, ~9 releases over the ~12 months ending in March 2026 |
| Last commit on main | 2026-04-21 (dependabot bump); regular human commits before that |
| Stars / forks (May 2026) | 8,909 / 1,013 |
| Open issues | 57 |
| License | AGPL-3.0 (backend, since 2.1.1, Aug 2024); MIT (hanko-elements, hanko-frontend-sdk) |
| Primary language | Go (~67%) |
| Top human contributors | `like-a-bause` (547), `FreddyDevelop` (406), `lfleischmann` (312), `FlxMgdnz` (164), `bjoern-m` (152). All appear to be Hanko GmbH employees. |
| Bus factor | Low. Top six contributors look like the company's engineering team; community contributions trail off into the single digits. If Hanko GmbH stops paying salaries, development effectively stops. |
| Governance | Single-vendor open core. No foundation, no external steering committee. |

**Funding / commercialization.** Hanko GmbH is a Kiel, Germany venture-
backed startup. Seed from HTGF (High-Tech Gründerfonds) plus PAYONE
founders Carl Frederic Zitscher and Jan Kanieß; €1.2M round led by
adesso ventures (with HTGF, SIVentures, and angels) reported in 2024.
Latka reports $272.2K revenue with a 7-person team in 2024.

The commercialization model is a managed cloud (Hanko Cloud) plus an
AGPLv3 self-hosted edition. The 2024 license change from MIT/Apache to
AGPL on the backend is the canonical "we want to deter SaaS competitors
from rehosting our backend" move; for self-hosters it is operationally
fine but it signals the company is serious about monetizing the cloud
product. The Series-A-class revenue (~$272K ARR on a 7-person team)
implies the cloud business is not yet self-sustaining and the project
is dependent on continued investor patience. **Five-year survival is
plausible but not guaranteed**; it sits in the "well-funded German
startup" bucket which has both upside (HTGF tends to nurture) and
downside (single-product SaaS in a Auth0/Clerk/WorkOS competitive
field).

## Security practices

- **CVEs / advisories.** No published GHSAs on the repo's security tab
  as of May 2026. No public CVE entries surfaced in search. The
  project supports private vulnerability reporting via GitHub.
- **No public third-party security audit** found. Hanko Cloud markets
  SOC 2 / ISO compliance for the managed product, but that does not
  attest the OSS code itself.
- **Substrate.** Go backend. Uses `zitadel/oidc` for OIDC client work
  and standard Go crypto for sessions/JWTs. Recent dependabot churn
  shows an active patch posture (multiple `golang.org/x/crypto` and
  `coreos/go-oidc` bumps in April 2026).
- **Default-secure posture.** PKCE on by default for OAuth flows since
  2.2 (Oct 2024). Server-side sessions with remote revocation.
  AGPL backend, MIT frontend. The 2.5 changelog mentions "SQL
  injection prevention" hardening, which is the kind of release note
  that cuts both ways: good they fixed it, slight smell that it landed
  in 2026 on a project that has been live since 2022.
- **Passkey / WebAuthn.** First-class. This is the project's reason
  for existing. WebAuthn is the primary credential, with
  email passcodes, passwords, and OAuth as fallbacks.

## Capabilities for our app stack

The decisive answer to the user's specific concern: **the prior is
correct. Hanko is a passkey-as-a-service backend that apps embed, not
an IDP that other apps consume.**

Concretely:

- **OIDC IdP role: NO.** PR #869 ("Application Integration: OIDC
  endpoints") attempted to add `/authorize`, `/token`, `/userinfo`,
  `/jwks` so third-party apps could federate to Hanko. Maintainers
  closed it in June 2023 with: they "don't want to support OIDC
  Provider capabilities," developer experience "would suffer a lot"
  with redirect flows and login UI on the backend, and they lack
  capacity to maintain "the huge code surface OIDC/OAuth would put on
  our shoulders." Issue #1320 (Feb 2024) asks for the same thing,
  closed without action. The official feature list as of 2.5 includes
  "Custom OIDC/OAuth connections" — that means Hanko as an OAuth/OIDC
  *client* of upstream providers (Google, GitHub, generic), not Hanko
  as a provider.
- **SAML IdP role: NO.** Hanko's SAML support is SP-only. Per the
  enterprise-SSO docs: "A SAML SSO integration requires configuration
  at the Service Provider (SP, your Hanko project in this case) and
  the Identity Provider (IdP)." Hanko receives SAML assertions from
  Okta / Entra / Google Workspace / Auth0; it does not issue them to
  downstream apps. The "IdP-initiated SSO" feature added in 1.4 is
  Hanko *accepting* IdP-initiated requests as the SP, not Hanko
  *being* the IdP.
- **LDAP / LDAPS: NO.** No LDAP server, no LDAP-as-IdP consumer. Not
  in the docs index, not in the config schema, not on the roadmap.
- **Forward-auth (Caddy/Traefik `forward_auth`): NO.** Not in the
  docs. The architecture model is "embed our JS SDK in your app and
  validate Hanko-issued JWTs server-side"; there is no
  `auth_request`-style endpoint pattern. You cannot put Hanko in
  front of Navidrome or the *arr stack with a reverse-proxy auth
  hook.
- **SCIM: NO.** Not surfaced in docs or release notes.
- **OAuth2 client-credentials grant: unclear at best.** Hanko's OAuth
  support is user-facing social-login flows (auth code + PKCE).
  Machine-to-machine client-credentials is not advertised; you would
  need to fake it with API keys or Hanko's session JWTs.
- **WebAuthn / passkeys: YES, primary.**
- **Webhooks: YES.** Out-of-band events for downstream sync.

### Per-app fit

| App | Hanko required protocol | Hanko supports? | Notes |
|---|---|---|---|
| Vaultwarden | OIDC IdP | NO | Hanko cannot issue ID tokens to Vaultwarden. |
| Mealie | OIDC IdP | NO | Same. |
| Audiobookshelf | OIDC IdP | NO | Same. |
| Immich | OIDC IdP | NO | Same. |
| BookLore | OIDC IdP | NO | Same. |
| oCIS | OIDC IdP | NO | Same. |
| Grafana | OIDC IdP | NO | Same. |
| GitLab | OIDC IdP | NO | Same. |
| Jellyfin | LDAPS | NO | No LDAP server. |
| Navidrome | forward-auth + Subsonic API bypass | NO | No forward-auth endpoint. |
| *arr stack | forward-auth + API bypass | NO | Same. |
| vLLM | OAuth2 client-credentials | NO | No machine-to-machine grant. |
| Tailscale custom IDP | OIDC + WebFinger | NO | No OIDC IdP role; WebFinger not advertised. |

Score: **0 of 13 native fits.** Every integration would require
building a shim service in front of Hanko (e.g., write your own OIDC
provider that authenticates users against Hanko's flow API and issues
its own tokens). At that point you are using Hanko as a passkey
credential store and reimplementing every protocol an IDP exists to
provide.

## Customizability

Where Hanko genuinely shines, just not for our shape:

- **Hanko Elements (MIT-licensed web components)** — drop-in
  `<hanko-auth>` and `<hanko-profile>` with CSS variable theming,
  i18n, and dark mode.
- **Headless via Frontend SDK** — bring your own UI in any framework;
  drive the Flow API directly from JS. This is well documented and is
  the project's pitch to product teams.
- **Custom flows** — flow-locking, configurable third-party prompt
  parameters, custom session claims, customizable user metadata
  (private/public/unsafe scopes) all landed in the 2.0–2.3 series.
- **Branded email templates / passcodes** — i18n + custom translations.

For a hypothetical app where Hanko *were* the right shape, the
customizability story is one of the strongest in the field.

## Architecture

Multi-container, Postgres-backed:

| Component | Purpose |
|---|---|
| `hanko` (backend) | Public API on :8000, admin API on :8001 |
| `hanko-migrate` | Schema migrations, runs once |
| `postgresd` | PostgreSQL (12+ in quickstart) |
| `mailslurper` (dev) or external SMTP | Outbound email for passcodes |
| `elements` (optional) | Static web-component bundle if you embed |
| Optional: Redis | Session/cache if scaled out |

Footprint: a Go binary plus Postgres. No JVM, no Node runtime in the
hot path. Comparable in resource cost to Authelia or Zitadel; heavier
than a single-binary kanidm. AWS KMS supported as an external key
provider since 2.4 if you want HSM-backed signing keys (which is a
nice posture signal even if you would never use AWS for it).

## Community + ecosystem

- **r/selfhosted traction: effectively zero.** A search for "Hanko"
  in self-hosted-stack roundups, top-N homelab software lists, and
  awesome-selfhosted does not surface it. The community is product
  developers, not homelabbers. This matters for the "is anyone else
  doing this" sanity check: nobody self-hosting a household stack is
  reaching for Hanko.
- **App integration tutorials** are oriented at "how to add Hanko
  login to your Next.js / React / Svelte / Vue app," not at "how to
  put Hanko in front of Jellyfin."
- **Discord / Slack community** exists; pace of activity is moderate.
- **No OIDC-IdP integration guides exist** because the role does not
  exist.

## AI/LLM contribution policy

The repository's `CONTRIBUTING.md` does not mention AI-assisted code,
LLM contributions, AI-Assisted commit trailers, DCO, or CLA. The
project uses Conventional Commits and standard Go formatting; that is
the entire bar. This is laxer than the bootc / kernel / systemd
discipline you have been operating under upstream — neither
particularly progressive nor particularly cautious. For a downstream
consumer this is irrelevant; for someone wanting to upstream patches
it means the policy bar is "whatever the maintainers decide on a
given PR."

## Pros for our use

(Almost all of these are dominated by the cons in the next section,
listed for completeness.)

- Excellent passkey/WebAuthn primary-credential implementation.
- Clean Go codebase, monthly release cadence, active dependabot
  hygiene.
- Strong customizability story (BYO UI, themed components, custom
  flows, custom session claims).
- AGPLv3 backend keeps the OSS edition honest and prevents a soft
  bait-and-switch to source-available.
- Funded company with a real engineering team (~7), reasonable
  five-year survival prior.

## Cons for our use

- **No OIDC IdP role.** Maintainers have declined to add it on scope
  grounds. Eight of our thirteen apps need exactly this.
- **No SAML IdP role.** SAML is SP-only.
- **No LDAP server.** Jellyfin's only first-class auth path is
  unavailable.
- **No forward-auth.** Navidrome and *arr-stack pattern is unavailable.
- **No SCIM.** No way for downstream apps to sync user/group changes.
- **Single-vendor governance.** If Hanko GmbH pivots or fails, the
  project effectively halts; no foundation backstop.
- **Zero homelab community.** No tutorials, no shared configs, no
  troubleshooting threads in the demographic that matches our
  deployment.
- **Architectural mismatch is structural, not a missing feature.**
  Even if PR #869 had been accepted, the project's stated design
  ethos (auth-as-a-library embedded in your app, not auth-as-a-
  redirect-target) means the IdP role would always be a second-class
  citizen in this codebase.

## Verdict

**RED.** Hanko fails on capability fit, not maintenance or
security. Of the three stated selection criteria, only criterion 3
(customizability) is favorable; criterion 1 (sustainability) is
acceptable-with-reservations; the implicit criterion (capabilities
for our app stack) is a hard zero. Evaluating Hanko further is a
sunk-cost trap — there is no configuration, no plugin, no
contribution path that turns a passkey-embed-backend into a
forward-auth + LDAP + OIDC IdP that 13 apps consume.

Recommend dropping Hanko from the shortlist and continuing the
evaluation with Authelia, voidauth, Zitadel, and kanidm.

## Sources

- GitHub: <https://github.com/teamhanko/hanko> (repo metadata via gh API, May 2026: 8,909 stars / 1,013 forks / 57 open issues / pushed 2026-04-30)
- README: <https://github.com/teamhanko/hanko/blob/main/README.md>
- Releases: <https://github.com/teamhanko/hanko/releases>
- Docs index: <https://docs.hanko.io/>
- SAML SSO docs (Hanko-as-SP): <https://docs.hanko.io/guides/enterprise-sso/introduction>
- PR #869 (OIDC provider endpoints, closed/rejected): <https://github.com/teamhanko/hanko/pull/869>
- Issue #1320 (generic OIDC provider, closed): <https://github.com/teamhanko/hanko/issues/1320>
- Custom OAuth connections (Hanko-as-client): <https://www.hanko.io/updates/custom-oauth-connections>
- IdP-initiated SAML (Hanko-as-SP): <https://www.hanko.io/updates/idp-initiated-sso-with-saml>
- Quickstart docker-compose: <https://github.com/teamhanko/hanko/blob/main/deploy/docker-compose/quickstart.yaml>
- Hanko 1.2M EUR funding round: <https://www.hanko.io/blog/hanko-raises-1-2m>
- HTGF investment: <https://www.htgf.de/en/htgf-investment-hanko-io/>
- Latka revenue profile: <https://getlatka.com/companies/hanko>
- Cerbos 2026 OSS auth comparison: <https://www.cerbos.dev/blog/best-open-source-auth-tools-and-software-for-enterprises-2026>
- Hanko public roadmap: <https://teamhanko.notion.site/520e292df402459db43fd7266e5a1371>
