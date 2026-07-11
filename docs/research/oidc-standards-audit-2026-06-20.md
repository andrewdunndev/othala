# othala OIDC / Identity Standards-Alignment Audit (2026-06-20)

Multi-agent audit of othala's OIDC/identity design against OIDC Core / OAuth2 /
OIDC security BCP + de-facto conventions (Keycloak/Okta/Entra/Auth0/Authentik).
7 dimensions scanned (claims emission, standard claims/scopes, auth-code+PKCE,
discovery/userinfo/jwks, logout, identity-matching, consent/client-registration),
48 raw findings deduped + prioritized.

## 1. Headline verdict

othala is, on the whole, a **conformant and notably well-hardened** OIDC
deployment. The protocol-critical surfaces are correct by construction: it
delegates Discovery/JWKS/UserInfo/end_session wholesale to Ory Hydra v26.2.0 (no
shadow handlers), restricts every client to authorization_code + refresh_token
with response_types=code (no implicit/hybrid), uses the stable Kratos identity
UUID as a public `sub`, gates refresh tokens on offline_access, and defends the
consent/login/logout challenge handlers with action-scoped CSRF, subject-binding,
and a fail-closed access gate that re-runs before any skip_consent auto-accept.
The deviations concentrate in two places: **(a) custom-claim semantics** — the
`groups`/`roles` claim collapses to a single server-resolved role instead of the
full membership array, and claims are not gated by granted scope; and **(b)
single-logout reality vs. documentation** — back-channel logout is plumbed but no
production client registers a URI, and the user-facing logout never propagates to
RPs. None break the protocol; they break the *contract adopters expect*.

## 2. HIGH-severity deviations (by impact)

**H1 — `groups` claim is a single precedence-resolved role, not the full array.**
`lookupRole` returns at most one role (first-match in stored group order,
`claims.ts:145-152`); its `claim_emit.groups` literal then **overwrites** the
real membership array via `deepMergeClaims` (arrays last-write-wins,
`claims.ts:201-202`), even though `buildIDTokenClaims` first set the true array
(`claims.ts:90-93`). A user in both `larder`+`larder-admin` (or `family`+`friends`)
silently loses the losing membership; RPs doing `admin_group in claims.groups`
mis-evaluate. Standard: de-facto SCIM `groups` convention = emit the full array,
RP decides precedence. Fix: set-union array claims in `deepMergeClaims`, or keep
base `groups` authoritative and let role `claim_emit` contribute only scalar app
attrs (e.g. `grafana_role`). No manifest schema change.

**H2 — ID-token claims are not scope-gated.** `composeIDTokenClaims` builds
`email`/`email_verified`/`name`/`preferred_username` unconditionally;
`consent.requested_scope` is read only to set `grant_scope`, never to filter
claims. An `openid`-only client still receives full PII. Standard: OIDC Core §5.4.
Fix: thread `requested_scope` into `composeIDTokenClaims`; gate `email*` behind
`email`, `name`/`preferred_username` behind `profile`, `groups` behind the
`groups` scope. Low practical exposure today (one client requests all scopes) but
the IdP is OSS/multi-tenant by design.

**H3 — user-facing portal logout is Kratos-only (no single-logout).**
`auth/logout.astro:12-42` runs only the Kratos browser logout; never hits Hydra's
`end_session_endpoint`, never revokes Hydra sessions, never fires back-channel.
A user who "logs out" kills only the IdP session; every RP keeps its app session.
Fix: route through `revokeSubject` (or document it as Kratos-only).

**H4 — no production client registers `backchannel_logout_uri`.** The registrar
supports it (`register-clients.ts:147-150`) but `larder.yaml`/`observe.yaml` set
none, so even admin "sign out everywhere" produces zero RP-side logout. Fix: add
`backchannel_logout_uri` to `larder.yaml` (Mealie supports it) + future clients.

**H5 — no adopter guidance to key RPs on `sub`; every documented recipe links on
email/username.** `sub` is a correct immutable UUID, but `docs/per-app-oidc.md`
wires GitLab/Immich/Mealie on email/username — and both `email` and `username`
are user-editable Kratos traits. A member changing email keeps the same `sub` but
orphans every email-linked RP account. Standard: OIDC Core §5.7 (only `sub` is
stable). Fix: "Account linking & the durable key" doc section — pin matching to
`sub` where supported (e.g. Immich `OAUTH_STORAGE_LABEL_CLAIM=sub`), document the
email-change relink runbook, optionally make `username` admin-only.

> Dedup: H1 is one root cause (`lookupRole`/`deepMergeClaims`) reported under 4
> dimensions. H3/H4 are the two halves of "SLO doesn't actually happen."

## 3. MEDIUM deviations

- **Server-side precedence is an anti-pattern for array claims** (collateral of
  H1); resolves once H1 lands. For RPs needing one scalar role, drive precedence
  from an explicit ordered `roles:` declaration, not emergent alphabetical sort.
- **`groups` scope grant/denial has no effect** (sibling of H2) — emission keyed
  on `emit_groups_claim`, not the granted scope; consent screen is untruthful.
- **UserInfo advertised but zero e2e coverage** — smoke asserts only discovery
  issuer + JWKS; nothing GETs `/userinfo`. Add an id_token↔UserInfo equivalence test.
- **PKCE not enforced for confidential clients** — `hydra.yml:76-85`
  `pkce.enforced:false`, public-only true; effectively OFF for all (confidential)
  clients (Tailscale RP can't do PKCE, no per-client knob). Check Hydra v26.2.0
  per-client `require_pkce`; else record in `.deviations.yaml`.
- **Registrar update is full-PUT wholesale replace** (RFC 7592) — out-of-band
  Hydra state destroyed on re-apply; a PUT omitting `client_secret` with
  `allowMissingSecret` can blank the secret. CLI path can't hit it; library API
  can. Fix: pre-PUT diff or `patchOAuth2Client`; guard secret-preserve.
- **Docs overstate the back-channel guarantee** — `STATUS.md`/`security-review-
  2026-06-07.md` say `revokeSubject` "fans out back-channel logout"; it posts no
  logout token (none registered, per H4). Align to the honest admin-UI copy.

## 4. What othala already gets right (strong base)

- **Delegation:** Discovery/JWKS/UserInfo/`end_session` Hydra-native (no shadow
  handlers); issuer byte-match + RS256 JWKS gate-asserted.
- **Flow hardening:** authorization_code+refresh only, no implicit/hybrid;
  `client_secret_basic` with url-safe hex secrets (bcrypt cost 14); refresh gated
  on `offline_access` with rotation+reuse-detection; consent grants exactly the
  requested scope/audience, fail-closed audience↔redirect match; redirect-URI
  exact-match via Hydra; CORS trimmed to GET/POST + pinned origin.
- **Identity:** `sub` = immutable Kratos UUID, `subject_types:[public]`; mutable
  `username` emitted as `preferred_username` (never `sub`); skip-path re-verifies
  `identity.id === login.subject`; `email_verified` derived per-address.
- **Consent/logout integrity:** consent POST = session→CSRF→subject-match→re-gate
  →accept; logout-challenge subject-binding (FIX-F); `skip_consent` first-party
  only with the access gate running BEFORE skip auto-accept (keep a contract test).
- **Claims data model:** `group_role_map`/`claim_emit` are pure validated manifest
  data (no hardcoded group names); `validateClients` rejects dangling role refs;
  the `groups` claim is already the flat-string-array shape — only its *contents*
  are wrong (H1).

## 5. Remediation sequence

**Wave 1 — single PR, localized, highest leverage:**
1. H1 — fix `deepMergeClaims` array set-union (stop role `claim_emit.groups`
   shadowing the base array). No manifest changes.
2. H2 — thread `consent.requested_scope` into `composeIDTokenClaims`; gate
   email/profile/groups. Same two functions as H1.
   Ship with one e2e: minimal-scope client gets only `sub`+granted claims;
   multi-membership user emits the full `groups` array.

**Wave 2 — config + manifest + docs (small):**
3. H4 — `backchannel_logout_uri` on `larder.yaml`.
4. H3 — wire `revokeSubject` into the portal logout link (or document Kratos-only).
   H3+H4 together + a back-channel-sink e2e make SLO real.
5. Doc mediums — correct STATUS.md/security-review wording; add the UserInfo e2e.

**Wave 3 — design decisions (defer, not release-blocking-as-code):**
6. H5 — "durable key" doc section + email-change relink runbook + optional
   admin-only `username`.
7. PKCE — upstream-capability check on Hydra v26.2.0 before enforce-vs-record.
8. Registrar PUT→PATCH / pre-flight diff.

**Launch gate:** the OSS release should not ship without at least the H5
*documentation* and the H3/H4 SLO-contract statement — both are "deployed
behavior doesn't match what the docs promise."
