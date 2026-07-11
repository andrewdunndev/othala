# Ory ecosystem survey + Oathkeeper deep dive

Research doc, not a decision record. Captures the current shape of the
Ory product family, settles whether Polis is real, and answers the
question "should we put Oathkeeper in front of the auth pod" with
enough depth to act on later.

Cutoff for citations: May 2026. All version numbers and release dates
were verified against `github.com/ory/*` and `ory.com/docs` on the date
of writing.

## Section 1: Ory ecosystem (Task A)

### How the products fit together

Ory has split its lineup into three planes:

1. **Ory Network**: managed multi-tenant SaaS at `ory.com`. Hosts the
   open-source engines, plus closed UI/console layers. The same release
   train as the OSS components: Ory Network and the OSS repos now ship
   under a unified version (v25.4.0 in November 2025, v26.x through 2026).
2. **Ory Open Source**: the Apache-2.0 engines you can self-host (Kratos,
   Hydra, Oathkeeper, Keto, Polis, plus libraries Fosite, Ladon, x).
3. **Ory Enterprise License (OEL)**: the same engines as OSS plus
   commercial support, SLA, and a few addons (e.g., the Account
   Experience UI). Sold per seat / project.

Polis (formerly BoxyHQ Jackson) is the newest addition: Ory acquired
BoxyHQ and rebranded the SAML/SCIM bridge in 2025. It's now a first-class
Ory project with the same release cadence as Kratos and Hydra (v26.2.0
on 2026-03-20).

### Product table

| Product | Purpose | Shape | License | Latest release | Health | Fit for our stack |
|---|---|---|---|---|---|---|
| **Kratos** | Identity management: registration, login, sessions, recovery, MFA. | Go binary + Postgres. | Apache-2.0 | v26.2.0 (2026-03-20) | 13.6k stars, 216 open issues, pushed daily. | **Yes (in production).** Already the substrate. |
| **Hydra** | OIDC OP / OAuth2 AS. Headless: delegates login + consent to a UI you write. | Go binary + Postgres. | Apache-2.0 | v26.2.0 (2026-03-20) | 17.1k stars, 131 open issues. Active. | **Yes (in production).** Already the substrate. |
| **Oathkeeper** | Identity & Access Proxy / decision API. Authenticates, authorizes, and mutates HTTP requests at the edge. | Go binary, no DB. Reverse proxy or decision API. | Apache-2.0 | v26.2.0 (2026-03-20) | 3.6k stars, 99 open issues, 33 open PRs. Active. | **Maybe later.** See section 4. |
| **Keto** | Zanzibar-style permission server (ReBAC). | Go binary + Postgres / SQLite / CockroachDB. | Apache-2.0 | v26.2.0 (2026-03-20) | 5.3k stars, 63 open issues. Active. | **No.** Family ACLs at 5-25 users do not need a permission server; per-app `consent.role_map` covers our cases. |
| **Polis** | Enterprise SSO bridge: terminates SAML and OIDC from external IdPs and re-presents them as a single OIDC source. SCIM 2.0 directory sync. | Node.js + Postgres / MySQL. | Apache-2.0 (OSS) | v26.2.0 (2026-03-20) | 2.2k stars, 21 open issues. Active. | **No.** We are the IdP, not a relying party for someone else's IdP. Polis is for B2B SaaS that needs to accept customer SAML. |
| **Elements** | React component library for Kratos self-service flows. | npm package. | Apache-2.0 | Tracks main release train. | Active. | **No.** We have Astro + `@dunn.dev/design`. |
| **Account Experience** | Hosted/Enterprise default Kratos UI. | OEL (closed). | Commercial. | Network. | Active. | **No.** Astro portal already serves this role. |
| **Actions** | Custom logic hooks in identity flows (Network feature; OSS via Kratos webhooks). | Network or OSS webhooks. | Mixed. | Tracks. | Active. | **Already using.** Our recovery-gate webhook is this pattern. |
| **Hydra Maester** | K8s CRD controller that reconciles `OAuth2Client` resources into Hydra. | Go binary, K8s controller. | Apache-2.0 | Tracks. | Community-maintained per repo banner. 44 stars. Active (last push 2026-04-29). | **No.** No K8s. Quadlets + `clients/*.yaml` already handle this. |
| **Oathkeeper Maester** | K8s CRD controller for Oathkeeper rules. | Go binary, K8s controller. | Apache-2.0 | Tracks. | Community-maintained. 36 stars. Active (last push 2026-04-30). | **No.** No K8s, and we wouldn't run Oathkeeper at family scale anyway. |
| **Fosite** | OIDC/OAuth2 SDK for Go (the engine inside Hydra). | Go library. | Apache-2.0 | v0.x; pushed 2025-11-20. | 2.5k stars. Library, not a service. | **N/A.** Indirect dep of Hydra. |
| **Ladon** | Authorization SDK for Go (predecessor of Keto). | Go library. | Apache-2.0 | Pushed 2025-10-22. | 2.5k stars. | **N/A.** Library. |
| **CLI** | `ory` command for managing Network projects. | Go binary. | Apache-2.0 | Pushed 2026-04-24. | Active. | **No.** We don't use Ory Network. |
| **SDK / client-* repos** | Auto-generated OpenAPI clients for every product, in Java / Go / Rust / Python / PHP / Ruby / TS / Dart. | Per-language packages. | Apache-2.0 | Tracks. | Auto-generated. | **As needed.** We import `@ory/client-fetch` in the Astro portal. |
| **kratos-selfservice-ui-*** (node, react-nextjs, react-native) | Reference UIs for Kratos self-service flows. | Node / Next / RN. | Apache-2.0 | Active. | Reference, not production. | **No.** Astro portal supersedes. The lab Caddyfile still proxies the Node UI for fallback during the cutover; production drops it. |
| **k8s** (Helm charts) | Helm charts for the whole estate. | Helm. | Apache-2.0 | Pushed 2026-04-23. | Active. | **No.** Quadlets, not Helm. |
| **Terraform provider** | Manage Ory Network resources from TF. | TF provider. | Apache-2.0 | Pushed 2026-05-04. | Active. | **No.** Network-only. |
| **Dockertest, Herodot, Graceful, x, Pop (fork), Mail (fork)** | Internal Go libraries used across the engines. | Go libraries. | Apache-2.0 | Active. | Library. | **N/A.** Indirect deps. |
| **Lumen, Rerag-rebac, MockSAML, MockFedCM, claude-plugins, mcp** | Newer experiments: local code search, RAG with Zanzibar ACLs, SAML/FedCM mocks, AI-adjacent tooling. | Various. | Apache-2.0. | Recent. | Experimental. | **No.** Not relevant to the auth pod. |
| **Awesome-ory** | Curated community examples. | Markdown + samples. | Apache-2.0 | Pushed 2026-02-05. | Reference. | **As reference.** |

Sources:
- `github.com/ory` repo list (gh API, May 2026 snapshot)
- [Ory docs welcome page](https://www.ory.com/docs/welcome)
- [Polis docs landing](https://www.ory.com/docs/polis)
- [Polis launch announcement](https://www.ory.com/blog/introducing-ory-polis-for-enterprise-single-sign-on)

### Things I noticed worth flagging

- The OSS engines now ship **synchronized release numbers** under the v25.x
  / v26.x train (Kratos, Hydra, Oathkeeper, Keto, Polis all hit v26.2.0 on
  2026-03-20). This is a 2025 change. Pinning a single train across the
  pod is now the recommended pattern, replacing the old per-product
  semver. Worth noting for our compose pins which still use legacy
  semver.
- **Fosite** moved into Hydra's monorepo for development but still ships
  separately as a library. No action for us.
- **Oathkeeper Maester and Hydra Maester** carry a banner stating they are
  "Maintained by the community, not an official Ory project." Avoid
  building load-bearing pieces on these unless you intend to maintain
  the controller yourself.
- **Account Experience** and the **Console** are the closed-source pieces
  Ory uses to upsell Network / OEL. Everything we run is in the OSS set.

## Section 2: Polis investigation

**Polis is a real Ory project.** Specifically:

- Repo: `github.com/ory/polis`. 2.2k stars, Apache-2.0, last pushed
  2026-05-04. v26.2.0 released 2026-03-20.
- Was BoxyHQ Jackson. Ory acquired BoxyHQ and rebranded; the previous
  v1.52.x line carried the BoxyHQ heritage, then jumped to v26.2.0 to
  align with the unified Ory release train.
- TypeScript / Node.js, not Go. Different stack from the rest of the
  engines.

**What it does**: Polis is a **bridge / proxy** that terminates SAML and
OIDC connections from external IdPs and re-presents them to your app as
a single OIDC source. It also implements SCIM 2.0 for directory sync
(provisioning users from an external IdP into your local store).

The canonical use case is B2B SaaS: your app speaks OIDC; your enterprise
customer has Okta / Entra / PingFederate / a SAML IdP. Polis sits between
them and translates. From your app's perspective, you only ever talk
OIDC; Polis handles the SAML mess.

**Does it apply to us?** No. Our shape is the inverse:

- We run the IdP (Kratos + Hydra). We are not a relying party for
  someone else's SAML.
- The 14 apps in the family stack speak OIDC or LDAP. Polis would only
  be relevant if we needed to accept logins from, say, Andrew's
  employer's Okta, and wanted to translate that into our local OIDC.
  Not the use case.
- The closest match for "import an external IdP" we might one day want
  is "let the family log in with Apple / Google" (we explicitly rejected
  this; see "no split identity" in user memory). If that ever changed,
  Polis would still be overkill; Kratos has a `social_signin` feature
  that handles OIDC-to-OIDC directly without a bridge.

**Was the user thinking of something else?** Unlikely. Polis is real,
the search hit it on the first query, and the description matches what
a homelab operator might surface as "an Ory thing I haven't placed yet."
The mention is best read as "noticed this exists, want to know if it's
relevant" rather than a typo.

Sources:
- [ory/polis GitHub](https://github.com/ory/polis)
- [Polis docs introduction](https://www.ory.com/docs/polis)
- [Polis launch blog](https://www.ory.com/blog/introducing-ory-polis-for-enterprise-single-sign-on)

## Section 3: Oathkeeper deep dive (Task B)

### 1. What it does

Oathkeeper is an **Identity & Access Proxy (IAP)** plus a **decision API**.
The repo's own description: "A cloud native Identity & Access Proxy /
API and Access Control Decision API that authenticates, authorizes, and
mutates incoming HTTP(s) requests. Inspired by the BeyondCorp / Zero
Trust white paper." It implements the Policy Enforcement Point pattern
from BeyondCorp.

Two ways to deploy:

1. **Reverse proxy mode**: Oathkeeper is on the request path, terminating
   the call from the user, applying a rule, and reverse-proxying to the
   upstream. This replaces the role of Caddy `forward_auth` snippets.
2. **Decision API mode**: Oathkeeper sits off-path; an existing API
   gateway (Envoy, Nginx, Ambassador, Caddy via `forward_auth`) calls
   Oathkeeper's `/decisions` endpoint to ask "is this request
   authorized?" Oathkeeper returns 200 with mutated headers if yes, or
   non-2xx if no.

The conceptual model has five primitives:

- **Authenticators**: validate the credential on the incoming request.
  One handler per credential type (cookie, bearer, JWT, OAuth2
  introspection, basic auth, anonymous, noop, unauthorized). Multiple
  authenticators can be tried in order; the first one that succeeds
  wins. Authenticators populate a `subject` and an `extra` blob that
  later stages consume.
- **Authorizer**: exactly one per rule. Decides whether the
  authenticated subject is allowed to perform the request. Handlers:
  `allow`, `deny`, `keto_engine_acp_ory` (calls Keto), `remote`,
  `remote_json`. The `remote_*` handlers POST to an HTTP endpoint and
  read the response, which is how you wire app-specific logic.
- **Mutators**: rewrite the outgoing request before it hits upstream.
  Handlers: `noop`, `header`, `cookie`, `id_token` (signs a JWT with
  Oathkeeper's keys), `hydrator` (calls an external API to enrich the
  session). Multiple mutators chain.
- **Error handlers**: control what happens when authn or authz fails.
  Handlers: `json` (machine-readable error response), `redirect` (302 to
  a login page), `www_authenticate`. Selected per rule.
- **Access rules**: bind a match (URL pattern + HTTP methods) to one or
  more authenticators, exactly one authorizer, mutators, and error
  handlers. Rules live in YAML or JSON. Source can be a static file, a
  remote URL, or both, with hot reload.

Request flow when running as proxy:

1. Request arrives at the Oathkeeper proxy port (default 4455).
2. Match the URL + method against the rule set. No match: 404 (or fall
   through to upstream if configured).
3. Iterate authenticators. First non-error handler wins. Populate
   `Session{Subject, Extra}`.
4. Run the authorizer. If denied, hand to the rule's error handler.
5. Run the mutators in order. Each can rewrite headers, set cookies, or
   replace the credential entirely (`id_token`).
6. Forward to `upstream.url`.

Sources:
- [Oathkeeper docs landing](https://www.ory.com/docs/oathkeeper)
- [Access rules docs](https://www.ory.com/docs/oathkeeper/api-access-rules)
- [Authenticators docs](https://www.ory.com/docs/oathkeeper/pipeline/authn)
- [Mutators docs](https://www.ory.com/docs/oathkeeper/pipeline/mutator)

### 2. Deployment shape

Single Go binary, no database. Runs as `oathkeeper serve` and listens on
two ports by default:

- **4455**: proxy / API surface (handles real traffic)
- **4456**: API for `/health`, `/decisions/*`, JWKS (`/.well-known/jwks.json`)

State requirements:

- **Configuration file** (YAML / JSON / TOML) for handler enablement and
  global settings.
- **Access rules file or URL** (YAML / JSON). Hot-reloadable.
- **JWKS keys** for the `id_token` mutator. Can be a local JSON file or
  fetched from a URL. No database; keys are loaded into memory.
- No persistent state. No Redis, no Postgres. The session cache (when
  using `cookie_session`) is short-TTL in-memory.

Container shape: official image `oryd/oathkeeper:v26.2.0`. Same operator
ergonomics as the other engines. Memory footprint at idle is small (Go
binary, low MB range); under load the cache and rule evaluator dominate.
I could not find a published RSS benchmark; community issues mention an
old memory leak in v0.40.3 that was fixed.

In K8s land, Oathkeeper Maester reconciles `Rule` CRDs into the rule file.
For us (Quadlets, no K8s), the rules file is just a config artifact
managed by pyinfra, same as `kratos.yml`.

### 3. Configuration model

Two files:

**oathkeeper.yml** (per-handler enable/disable, global defaults):

```yaml
serve:
  proxy:
    port: 4455
  api:
    port: 4456

access_rules:
  matching_strategy: regexp
  repositories:
    - file:///etc/oathkeeper/rules.yml

authenticators:
  cookie_session:
    enabled: true
    config:
      check_session_url: http://kratos:4433/sessions/whoami
      preserve_path: true
      extra_from: "@this"
      subject_from: "identity.id"
      only:
        - ory_kratos_session
  oauth2_introspection:
    enabled: true
    config:
      introspection_url: http://hydra:4445/oauth2/introspect
      scope_strategy: exact

authorizers:
  allow:
    enabled: true
  remote_json:
    enabled: true

mutators:
  id_token:
    enabled: true
    config:
      issuer_url: https://dag.dunn.dev/oathkeeper
      jwks_url: file:///etc/oathkeeper/jwks.json
      ttl: 60s
  header:
    enabled: true
  noop:
    enabled: true

errors:
  fallback: [redirect]
  handlers:
    redirect:
      enabled: true
      config:
        to: https://home.dunn.dev/auth/login
        when:
          - error: [unauthorized, forbidden]
            request:
              header:
                accept: ["text/html"]
    json:
      enabled: true
```

**rules.yml** (one entry per route):

```yaml
- id: navidrome:web
  upstream:
    url: http://navidrome:4533
    preserve_host: true
  match:
    url: https://tune.dunn.dev/<.*>
    methods: [GET, POST, PUT, DELETE]
  authenticators:
    - handler: cookie_session
  authorizer:
    handler: remote_json
    config:
      remote: http://consent:4477/authz/check-group
      payload: |
        {"subject":"{{ print .Subject }}","group":"access-tune"}
  mutators:
    - handler: header
      config:
        headers:
          X-User: "{{ print .Subject }}"
          X-Email: "{{ print .Extra.identity.traits.email }}"
          X-Username: "{{ print .Extra.identity.traits.username }}"
  errors:
    - handler: redirect
      config:
        to: https://home.dunn.dev/auth/login?return_to=https://tune.dunn.dev
```

Matching uses regex by default (glob optional). Patterns are
`<...>`-bracketed. Per-route, no annotations on the upstream service.
Source for the cookie_session shape against Kratos: confirmed in the
canonical Ory zero-trust IAP guide and community examples.

Sources:
- [Access rules schema](https://www.ory.com/docs/oathkeeper/api-access-rules)
- [Zero-Trust IAP guide using Kratos + Oathkeeper](https://www.ory.com/docs/kratos/guides/zero-trust-iap-proxy-identity-access-proxy)
- [Connect to Hydra OAuth2 introspection](https://www.ory.com/docs/oathkeeper/oauth2-token-introspection-hydra)

### 4. Active maintenance

Healthy by every signal I checked.

- **Latest stable**: v26.2.0 on 2026-03-20.
- **Previous major**: v25.4.0 on 2025-11-07. Big version jump in 2025
  was the consolidation into the Ory monorepo and unified release train.
- **Repo activity**: `pushed_at: 2026-05-04`, 1690 commits on master.
- **Open**: 99 issues, 33 PRs. PRs from 2026-02 through 2026-04 from
  multiple non-Ory contributors with apparent maintainer engagement.
- **Stars / forks**: 3552 / ~407.
- **No fork**: I searched; no notable community fork. The Maester
  controller is in-org and explicitly community-maintained, but the
  engine itself is Ory-stewarded.

Maintainer responsiveness: hard to score precisely without reading
issue threads, but the cadence of commits (multiple per week) and the
v25 → v26 monorepo migration both indicate active investment.

Source: gh API on `ory/oathkeeper` (May 2026).

### 5. Integration with Kratos and Hydra

This is the place Oathkeeper shines.

**Kratos sessions (cookie)**: the `cookie_session` authenticator points
at `http://kratos:4433/sessions/whoami`. Kratos returns the full session
JSON; Oathkeeper picks the subject via `subject_from: identity.id` and
exposes the rest as `extra`. Mutators can read any field with Go
template syntax:

- `{{ print .Subject }}` → `identity.id` UUID
- `{{ print .Extra.identity.traits.email }}` → email
- `{{ print .Extra.identity.metadata_admin.groups }}` → groups array
- `{{ print .Extra.authenticator_assurance_level }}` → `"aal1"` /`"aal2"`

This is exactly what we need to remove the "Caddy can't read JSON
fields" limitation called out in `forward-auth.caddy` and
`admin-session.caddy`. AAL-aware enforcement at the proxy becomes
possible: an authorizer (e.g., `remote_json` to a tiny check service, or
a `keto_engine_acp_ory` policy) can require AAL2 for `/admin/*`.

**Hydra access tokens (bearer)**: the `oauth2_introspection`
authenticator calls Hydra's `/oauth2/introspect` (admin port 4445). With
our admin port locked inside the pod, the introspection URL would be
`http://hydra:4445/oauth2/introspect`, which is fine.

Known gotchas for our setup:

- **Cookie domain**: our session cookie is on `.dunn.dev`. Oathkeeper's
  `cookie_session` only forwards the cookies you list under `only`; it
  does not concern itself with the domain. As long as Caddy passes the
  cookie through to Oathkeeper (which it will, since they share the
  parent domain), this works.
- **Session vs token semantics**: Kratos sessions and Hydra access tokens
  are distinct. A request to `tune.dunn.dev` carries `ory_kratos_session`,
  not a Hydra token; a request from a CLI consumer to a vLLM endpoint
  might carry a Hydra-issued access token instead. You'd write two
  authenticators per rule (try cookie first, fall back to bearer) or use
  separate rules per route.
- **AAL semantics**: Kratos returns `authenticator_assurance_level` in
  the whoami JSON. Oathkeeper has no built-in AAL handler; you'd
  implement AAL2 enforcement as a `remote_json` authorizer or a small
  inline template check. The Astro SSR pages already do this on
  `/admin/*` and that pattern stays.
- **id_token mutator**: signs a fresh JWT keyed off a JWKS Oathkeeper
  controls, not Hydra. If an upstream app expects a Hydra-issued JWT
  with Hydra's `iss`, the `id_token` mutator is the wrong tool; pass the
  Hydra token through with a `noop` mutator instead. The id_token
  mutator is a good replacement for our hand-rolled Caddy bearer compare
  on vLLM (Oathkeeper signs a token the upstream verifies via JWKS), but
  not a replacement for Hydra's role.

Sources:
- [Zero-Trust IAP guide (Kratos + Oathkeeper)](https://www.ory.com/docs/kratos/guides/zero-trust-iap-proxy-identity-access-proxy)
- [oauth2_introspection authenticator](https://www.ory.com/docs/oathkeeper/pipeline/authn)
- [Connect to Hydra introspection](https://www.ory.com/docs/oathkeeper/oauth2-token-introspection-hydra)

### 6. What it would replace in our current stack

Concretely, mapped to files in this repo:

| Current artifact | Replaced by |
|---|---|
| Caddy forward-auth snippet (Kratos whoami forward_auth + redirect; production config in the deploy repo) | `cookie_session` authenticator + `redirect` error handler |
| Caddy admin-session snippet (whoami forward_auth, app-layer AAL2; production config in the deploy repo) | `cookie_session` + `remote_json` authorizer enforcing AAL2 server-side |
| Hand-rolled bearer compare for vLLM in Caddy | `id_token` mutator (Oathkeeper-signed JWT) **or** `oauth2_introspection` if vLLM accepts Hydra tokens |
| Othala app `/admin/revoke-user` bearer auth (security review MEDIUM-1) | `oauth2_introspection` against Hydra + `remote_json` against a "is admin" check |
| Per-app `consent.role_map` claim emission in Hydra | **Not replaced.** This is Hydra consent territory, not Oathkeeper. |

Important: Oathkeeper does **not** replace the `consent:` block claim
emission. That's `id_token` claims minted by Hydra at OAuth2 consent
time, consumed by OIDC clients (Vaultwarden, etc.). Oathkeeper's
`header` mutator injects request-time HTTP headers, which is a
different surface used by apps that don't speak OIDC (Navidrome,
Sonarr/Radarr behind forward_auth). For an OIDC-native app, Oathkeeper
is in front of the app layer but does not sit in the OIDC flow itself.

So the split is:

- **OIDC-native apps** (Vaultwarden, Immich, Grafana, Forgejo, ...): Hydra
  emits id_token claims; Oathkeeper would only sit in front to enforce
  AAL2 or group membership at the proxy. Today Caddy does TLS and
  reverse_proxy, the apps handle their own OIDC.
- **Header-injection apps** (Navidrome / tune, Sonarr+Radarr / gather):
  today Caddy `forward_auth` to Kratos; tomorrow Oathkeeper
  `cookie_session` + `header` mutator. This is the cleanest win.
- **Bearer-protected APIs** (vLLM, consent admin port): today hand-rolled;
  tomorrow `oauth2_introspection` + `id_token` or pass-through mutator.
  Removes hand-rolled crypto comparison code.

### 7. What it can't do that our current stack does

- **OIDC consent flows**: no. Hydra owns the consent UX. Oathkeeper does
  not issue tokens, does not run a consent screen, does not manage
  OAuth2 clients. There is no overlap with Hydra's role.
- **Identity management**: no. Oathkeeper has no notion of registration,
  recovery, MFA, or password storage. Kratos owns that.
- **Webhook events**: no. Oathkeeper does not fire on identity events.
  Our recovery-gate webhook (Kratos `before_recovery` hook) cannot move
  to Oathkeeper. Webhooks remain a Kratos feature.
- **Admin UI for users**: no. The Astro admin UI stays where it is.
- **LDAP**: no. Oathkeeper is HTTP-only. The glauth-kratos bridge stays.

In short, Oathkeeper is purely a request-path enforcement layer. It does
not replace Kratos, Hydra, or the LDAP bridge.

### 8. Operational cost

Adding Oathkeeper to the auth pod means:

- One more Quadlet (`oathkeeper.container`) running the Go binary.
- Two more port reservations (4455 proxy, 4456 API). Both pod-internal
  if Caddy stays the public terminator and uses Oathkeeper as a
  decision API.
- Two more config files in pyinfra (`oathkeeper.yml`, `rules.yml`) plus
  a JWKS file if we use `id_token`.
- A JWKS rotation procedure for the id_token mutator (analogous to
  Hydra's `secrets.system` and `secrets.cookie`, except smaller scope).
- Memory footprint: small Go binary, expect tens of MB RSS at idle, low
  hundreds under load. No documented benchmark; would need to measure.

Runbook additions:

- Rule deploy: write rule to `rules.yml`, ship via pyinfra, Oathkeeper
  hot-reloads. No restart needed for rule changes.
- JWKS rotation: similar to Hydra cookie rotation: two-slot, dual-issue,
  rotate.
- Debugging: Oathkeeper has structured JSON logs and a `/decisions`
  endpoint that explains why a request was allowed or denied. Better
  than tailing Caddy access logs.

The cost is real but bounded. We already run six other services in the
auth pod (kratos, kratos-courier, hydra, consent, portal, postgres);
one more is incremental.

### 9. Family-scale fit

Honest assessment: Oathkeeper is overkill for the Caddy `forward_auth`
cases we have today.

- Two snippets (`forward-auth.caddy`, `admin-session.caddy`) cover three
  apps (Navidrome, Sonarr, Radarr). The "Caddy can't read JSON fields"
  comment is real but worked around: app-layer `X-Kratos-Groups` reads
  for app-supported headers, Astro SSR for AAL2 on admin paths.
- Adding Oathkeeper for three apps adds one service, one config surface,
  one runbook, and one more rotating key, against a saving of: removing
  one workaround comment and centralizing rule logic.
- The vLLM bearer compare and the consent admin-port bearer auth are the
  more compelling cases. Both are hand-rolled crypto; both are MEDIUM
  findings in the security review territory. Oathkeeper's
  `oauth2_introspection` authenticator on a small rule set replaces both
  with battle-tested code.

So at family scale: Oathkeeper does **not** earn its keep on the
Navidrome/Sonarr/Radarr forward_auth work alone. It **does** earn its
keep if you also fold in the bearer-protected internal APIs and the
admin-mux protections.

### 10. Migration cost (today)

Reading the production Caddyfile (in the deploy repo's `services/dag/`) and the
e2e harness Caddyfile (`e2e/caddy.Caddyfile`), the lift looks like:

1. Add `oathkeeper.container` Quadlet to the auth pod (~30 min).
2. Author `oathkeeper.yml` + initial `rules.yml` (~half a day for the
   six-or-so apps in scope).
3. Generate Oathkeeper JWKS, add to env / Bitwarden (~15 min).
4. Replace `import forward-auth navidrome 4533` with a Caddy block that
   does `forward_auth oathkeeper:4456 { uri /decisions }` (decision-API
   mode keeps Caddy as TLS terminator) **or** point Caddy directly at
   `oathkeeper:4455` and let Oathkeeper proxy to upstream (proxy mode).
   Decision-API mode is the lower-risk migration; proxy mode is
   cleaner but moves all reverse_proxy logic into rules.yml.
5. Update the Caddy forward-auth and admin-session snippets in the
   the deploy repo to call Oathkeeper instead of Kratos
   directly.
6. Cut over apps one at a time, validate, rinse, repeat. Each app: ~1h
   end-to-end.
7. Update runbooks (`docs/runbooks/`) for rule deploy, JWKS rotation,
   debug procedure.

Total estimate: 2-3 days of focused work for the full migration of the
header-injection apps and the two bearer-protected APIs. None of it is
on the production cutover critical path; Phase 5+ territory.

## Section 4: Recommendation

**Don't adopt Oathkeeper now. Revisit at Phase 5+.**

Today the auth substrate is feature-complete and security-reviewed. The
gaps Oathkeeper would close are real but small:

- Three header-injection apps using `forward_auth` to Kratos. Working,
  documented limitation.
- Two bearer-protected internal APIs with hand-rolled crypto compare.
  Working, MEDIUM-band findings.

The trigger that flips the answer is one of:

1. **A fourth or fifth app shows up that needs forward_auth + group
   gating + AAL awareness**, especially if any of them has a public-
   internet path. At that point the per-app workaround pattern
   collapses and a centralized policy point pays for itself.
2. **The bearer-protected APIs grow.** A second hand-rolled bearer check
   beyond vLLM and the consent admin port is the inflection. Three
   places running their own bearer compare is too many; centralize on
   `oauth2_introspection`.
3. **AAL2 enforcement needs to move below the SSR layer.** Right now
   the Astro page enforces AAL2 on `/admin/*`. If a non-Astro admin
   surface ever appears (e.g., Forgejo admin, Grafana admin needing
   AAL2 step-up), the SSR pattern doesn't generalize and Oathkeeper
   does.

Until one of those triggers fires, Caddy + per-app YAML is the right
shape. Family scale rewards "fewer moving parts" much more than it
rewards "centralized policy fabric."

If the trigger does fire, the migration is 2-3 days, no critical-path
risk, and lands in a place that's strictly better than the current
workarounds.
