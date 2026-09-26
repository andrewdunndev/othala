# Changelog

All notable changes to Othala are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The git tag is the authoritative version; `portal/package.json` mirrors it.
This CHANGELOG and git tags carry the deployed-instance release state.

## [Unreleased]

### Changed

- `kratos.yml`/`hydra.yml` set `request_log.disable_for_health: true` on both
  listeners, so health probes stop writing access-log lines. Hydra's admin
  listener logs them regardless: probe Hydra's public `/health/ready`, as e2e
  does (smoke A0).

## [0.6.1] - 2026-09-04

Evidence release: the login-tier logic that 0.5.0's outage slipped past is now
proven against the captured production flow on every push, passkey eviction is
corrected to the model Kratos actually allows, and e2e keeps its evidence.

### Changed

- **Passkey eviction is self-service, never an admin action.** Kratos refuses
  an admin DELETE of a passkey credential (400, upstream default), so the admin
  UI no longer offers it. The documented path is contain, recover, self-remove,
  delete-identity; the e2e P-block proves the real eviction (the victim removes
  the lost passkey in settings, the other session survives).
- Login tier derivation extracted into `deriveLoginTiers`, unit-tested against
  the real captured production flow and mutation-proven red on the 0.5.0 logic.
- Auth pages share one panel style; both admin user forms share one script
  component; `isSessionFresh` drops a guard that never changed the outcome.

### Fixed

- e2e renders the login journey in a real browser and hard-asserts all three
  tiers; passkey login is no longer fixme'd; CDP ceremonies wait
  deterministically; the N2 scrape retries then fails instead of skipping.
- e2e runs on MR, main and tag pipelines; verify and lint ride api pipelines so
  a lever run can never read greener than the push; flaky-then-green runs keep
  their first-attempt artifacts.
- The DOS-2 flood test carries a 60s budget: 8-9s on a SaaS small runner,
  27s under contention, which reddened a green merge.

## [0.6.0] - 2026-08-22

The outage-ending release: 0.5.0's broken login page fixed, e2e gated into
every pipeline (not just tags) so the gap that let it ship stays closed, and
an admin-hardening batch (session freshness, delete-lockout, secret-strength).

### Fixed

- **Login page rendered an empty step-up card for every anonymous login.**
  The webauthn glue `<script>` node Kratos emits on every flow was miscounted
  as a second-factor node, so an ordinary AAL1 login looked like an AAL2
  step-up with nothing in it — nobody could sign in. Shipped broken in
  0.5.0; this release ends the outage.
- CI: e2e and both image builds now run in **every** pipeline, not just
  tag-gated ones — the gap that let the login bug above ship green.
- Admin session freshness now enforced (`OTHALA_ADMIN_FRESHNESS_HOURS`,
  default 1h, fail-closed): a stale admin session steps up again instead of
  being trusted indefinitely.
- Identity delete refuses admin-marked targets (revoke first, which enforces
  last-admin) — closes a delete-the-last-admin lockout path.
- 32-byte minimum enforced on admin-port bearer secrets at boot.

### Changed

- Admin action handlers extracted to a dispatch table (behavior-preserving).
- Group classification single-sourced onto the group registry; `/admin/groups`
  identity groups are now env-seeded only.
- e2e: rate-limit zones N1/N2 and multi-context eviction P1 now proven live;
  the production Caddy image joined the test substrate; failure artifacts
  upload; Chromium runs its real channel (was silently the headless-shell).
- Routine dependency bumps (vitest, the pipeline component, mailpit and
  nodejs base-image digests).

### Known limitation

- Passkey click-to-session completion is still unproven end to end (I1/P2/P3
  fixme'd) — the first live passkey login discriminates whether the
  authenticator survives the click. #8 open.

## [0.5.0] - 2026-08-18

Docs convergence (corpus cut two-thirds, 16 ADRs folded into one
DECISIONS.md, gated by a prose-budget ceiling and a whole-index purity
scan), a truth pass, admin-triggered invite email (D1), a purity-gate
rewrite, CI/test consolidation onto vitest, and six at-a-glance diagrams
now live on othala.dunn.dev.

### Added

- **Admin-triggered invite email (D1)**: one button drives Kratos's own
  recovery flow server-side, no new mail machinery. Server-checked
  send-time address confirmation guards against misrouting; the decision
  record states and bounds the residual risk.
- **Six at-a-glance SVG diagrams** (trust boundary, session revocation,
  first credential, OIDC login, plus two prior) now live on
  othala.dunn.dev.
- **Architecture page** (`othala.dunn.dev/architecture/`): the six diagrams
  in narrative order with connective prose. The landing page now tells the
  project story and links Architecture, Guides, and the repo as entry
  points.

### Changed

- **Docs converged**: corpus cut two-thirds (50 files/9.3K lines ->
  24/3.3K); 16 ADRs and a duplicate access-model doc collapsed into one
  flat DECISIONS.md. New gates: a prose-budget ceiling and a whole-index
  purity scan on every push.
- **Truth pass**: the identity schema's stale group-order claim corrected
  to match the ranked resolver it describes; operator runbook mechanics
  moved to the deploy plane; DECISIONS.md/AGENTS.md rewritten
  present-tense; duplicated derivations collapsed to one canonical
  statement plus pointers.
- **check-purity.sh rewritten** as a data table (1769 -> 293 lines); the
  probe-harness suite retired for an inline self-test. Prose ceiling
  ratcheted to 175000 bytes.
- **Tests consolidated onto vitest** (portal drops node:test+tsx); one
  merged CI job replaces the split portal jobs; the pre-tag-check gap CI
  never ran is now wired shut. 740 portal tests green.

### Fixed

- **Private-catalog codenames purged** from test fixtures; the purity
  gate's app-name check hardened 10 -> 18 branches on violation shape,
  not literal words.
- CI: a runner checkout ownership mismatch was silently erroring the
  purity/portal-check jobs (VACUOUS, not green); `safe.directory` fixes
  it, and the now-unused `cmp` dependency is retired.

## [0.4.0] - 2026-08-13

Admin-POST and AAL2 step-up fixes, extensible Hydra CORS for browser-SPA
clients, the othala.dunn.dev docs site, and a decisions/docs rewrite that
stands the project alone from the operator's private deployment.

### Fixed

- **Admin POST reachability restored.** `Referrer-Policy: no-referrer` made
  Chromium send `Origin: null` on same-origin admin-form POSTs (issue-recovery,
  force-relogin, deactivate, delete, grant/revoke-admin, profile save), which
  Astro's `checkOrigin` CSRF gate rejected outright — every state-changing
  admin action 403'd. Changed to `Referrer-Policy: same-origin`, which keeps
  flow/consent_challenge tokens off cross-origin referrers while restoring the
  Origin header the gate needs.
- **AAL2 step-up form now renders on Kratos's natural redirect.** Detection
  depended on a `?aal=aal2` query param that Kratos's own AAL2-initiator
  redirect doesn't reliably preserve, so the step-up form (TOTP/webauthn/
  lookup_secret) never rendered via the natural login flow. Detection now
  derives from the flow object first (`requested_aal === 'aal2'`, or presence
  of the second-factor nodes), falling back to the query param only when
  there's no flow to inspect.
- Renovate: closed the two config gaps that let a stale pipeline-catalog
  `CATALOG_VERSION` ARG and a solo Playwright npm bump through undetected at
  the v0.3.0 tag — the ARG now tracks via an annotated customManager, the
  Playwright group has automerge off, and a shadow docker-manager dependency
  on the same ARG (which could have silently rewritten it again) is disabled.
- CI: the e2e job's runner tags retargeted after the QEMU runner host was
  rebuilt under a new label, which had left the e2e release gate unmatchable;
  the golden-path docs' secret-store key path corrected to match. The e2e
  job's failure
  artifacts now upload: the declared paths were absolute `/tmp` paths the
  runner refuses (two of them dead references with no writer), so every
  failure lost its diagnostics; the live log moved to `e2e/logs/`.

### Added

- **Extensible Hydra CORS.** `allowed_origins` for browser-SPA clients (e.g.
  oCIS Web) now renders from `OTHALA_CORS_ALLOWED_ORIGINS`, a comma-separated
  origin list, instead of a single hardcoded origin. Defaults to
  `OTHALA_PUBLIC_URL` alone, so e2e/lab behavior is unchanged.
- **`othala.dunn.dev` docs site**: a public Astro SSG site modelled on
  reference.dunn.dev (IBM Plex type, light/dark toggle, the estate design
  system via `@dunn.dev/reference`), deployed as a Cloudflare Worker. Ships a
  curated Guides section and, at the time, a Decisions index; the decision
  corpus it indexed was removed in a later pass.

### Changed

- **Decision records rewritten to deployment accuracy.** An audit compared the
  recorded decisions against the deployed system; six had drifted (the LDAP
  bridge was never deployed, the mTLS admin-proxy was reverted, the admin
  login-gate hook was retired). Two gaps were recorded rather than papered
  over: the admin marker isn't schema-enumerated, and break-glass is
  root-by-role with no dedicated identity. Two decisions were newly recorded —
  the hardening deviations from Ory defaults, and the client-CORS/topology
  model.
- **Docs stand alone from the operator's private deployment.** Six dated docs
  removed (decision.md, STATUS.md, three security-review snapshots, the
  network SVG) with all 44 inbound references repointed; every reference to
  the operator's private infra repo scrubbed to generic phrasing across the
  decision records, AGENTS.md, and code comments; the adopter-facing
  `.env.example` de-drifted (retired `OTHALA_ADMIN_IDS`, LDAP vars moved out);
  code/doc leaves thinned to current-state facts. The decision corpus, and the
  purity-gate rule that checked pointers into it, were both removed in a later
  pass.
- Bumped the shared `@dunn.dev/reference` design-system package (consumed by
  the portal and now also the new docs site) from `^0.2.0` to `^0.4.0`.

## [0.3.0] - 2026-07-01

Security hardening pass (CVP), access-model refactor, PII-safe
OpenTelemetry tracing, and a portal UX/pristine pass.

### Added (post-rc, folded at tag time)

- **Portal UX pass**: passkey-first login copy (Face ID / Touch ID), a
  dismissible first-run passkey-enrollment nudge, legacy relabeling in
  settings (security key = legacy 2FA; password = legacy clients only),
  in-flight disable-on-submit feedback on admin forms, and a11y/design-system
  purity fixes (contrast, nested landmarks, raw-color removal, chip/badge
  unification, mobile reflow).
- Per-node validation messages rendered in FlowNodes + login step-2/TOTP.
- Admin-recovery hardening: real recovery-refusal test; `::` and `""` admin
  wildcards blocked (T2-N/T2-O).
- Admin recovery switched to `createRecoveryCodeForIdentity` (Kratos
  v26.2.0+ compatibility).
- Decision records expanded: migration join-key/durable-key, capability
  groups, first-party skip-consent; docs decoupled from the shelved LDAP
  bridge.

### Changed

- **Admin authority is now keyed on the immutable identity `id`, not the
  user-editable `email` trait** (CVP-P1). The allowlist env var is renamed
  `OTHALA_ADMIN_SUBJECTS` → `OTHALA_ADMIN_IDS` and holds Kratos identity
  UUIDs. Closes a privilege-escalation path where a user could set their
  `email` trait (changeable via the self-service profile flow, which does not
  revoke the session) to an allowlisted address. **Breaking:** operators must
  set `OTHALA_ADMIN_IDS` to identity UUIDs (from `kratos identity list`), and
  must now set `OTHALA_CONTACT_RECIPIENT` explicitly — it no longer falls back
  to the admin allowlist (UUIDs are not email addresses).
- **Settings flow requires the highest available AAL** (CVP-P2):
  `selfservice.flows.settings.required_aal` `aal1` → `highest_available`, so a
  first-factor-only session can no longer enroll or change credentials on an
  account that has a second factor. Password-only and passkey-only users are
  unaffected; first-passkey enrollment is not blocked.
- **Access-model refactor**: portal now derives tile/gate group membership from
  a central group registry (`access-model` primitives). Each app manifest
  declares an `access_group`; the portal builds derived groups and enforces
  them at the forward-auth gate, replacing the ad-hoc per-tile logic. Includes
  per-app forward-auth gating for the deployment's own tiles.
- **AAL2 step-up removed from the admin gate**: admin authority is enforced by
  the `OTHALA_ADMIN_IDS` allowlist + a basic-auth + passkey session check
  instead of the Kratos AAL2 step-up challenge, eliminating the dead-end UX
  path for passkey-only admins.

### Added

- **Admin email-code login gate** (CVP-P3): a `login.after.code` web_hook
  (`/admin/login-gate`, reusing `RECOVERY_GATE_SECRET`) refuses passwordless
  email-code login for admin identities, mirroring the recovery gate. Admins
  authenticate via passkey or console, closing the transient-mailbox → admin
  AAL1 session path.
- **Edge identity-header stripping** (CVP-P4): the `forward-auth` and
  `admin-session` Caddy snippets now strip spoofable inbound identity headers
  (`X-Kratos-Groups`, `X-Remote-*`, `X-Forwarded-User/Groups/Email`,
  `X-Auth-Request-*`) before proxying upstream, so a logged-in user cannot
  forge group membership. Per-app group enforcement guidance corrected: it
  must be done via the OIDC access-gate or a server-side forward_auth endpoint,
  never a passed header.
- **PII-safe OpenTelemetry tracing**: opt-in OTLP tracing for the portal, Kratos,
  and Hydra. The portal SDK scrubs `url.query`, `http.url`, and
  `Authorization` headers from all spans before export; traces emit to the
  host Alloy receiver via `OTLP_INGEST_TOKEN`. Kratos and Hydra gain opt-in
  `tracing:` blocks in their configs. The redaction pass is tested with fixture
  assertions.
- **In-app OIDC client registrar** (`register-clients.mjs`): replaces the
  legacy `dag-apply-clients` shell script. Boots on startup and reconciles on
  `SIGHUP`; CI exercises it against the e2e manifest set.
- An **OIDC manifest** and a **forward-auth tile** shipped as example
  manifests, each gated on its own access group.
- **Env-var-name hardening**: manifest-lint rule 1a enforces uppercase env-var
  names; the registrar fails loudly on malformed entries; `SIGHUP` analysis
  added to the config module.
- **Detection-as-code** purity guards: OSS-purity, no-deprecated, and
  dated-debt rules enforced in `scripts/check-purity.sh` + CI.

### Security (dependency bumps)

- `nodemailer` → v9 (security; resolves upstream CVE advisory)
- `astro` → v6.4.6 (security)
- `esbuild` → ^0.28.0 (security)
- `tough-cookie` → v6 (security)

## [0.2.0] - 2026-06-04

The convergence release: a breaking move from a build-time app catalog to a
runtime manifest model, plus the rename to **Othala** ("Ory for your home").

### Added

- **Runtime manifest model.** Apps are now read at request time from
  `MANIFEST_DIR` (default `/etc/portal/manifests`). Each app is one unified
  `<slug>.yaml` carrying disjoint `presentation:` / `oidc:` / `consent:`
  blocks, with an optional sibling `<slug>.md` education page. Two loaders read
  one file: `lib/tiles.ts` reads `presentation:` for the dashboard tiles and
  `/apps/<slug>` detail pages; `lib/manifests.ts` reads `oidc:` / `consent:` to
  register the OAuth2 client and compute role-to-claim mappings. Both cache
  ~30s and invalidate on mtime, so adding, changing, or removing an app is a
  manifest-dir change with **no image rebuild**.
- **Functional dashboard contact form.** The dashboard request form is now
  real: `POST /api/request` (`lib/contact.ts` validation, rate-limit, and
  header-injection guard) sends over the shared SMTP relay via `lib/mailer.ts`
  (nodemailer). `OTHALA_SMTP_CONNECTION_URI` is the single relay shared by the
  Kratos courier and the form; the recipient is `OTHALA_CONTACT_RECIPIENT`,
  falling back to the first `OTHALA_ADMIN_SUBJECTS` entry. SMTP internals never
  leak to the client.
- **Generic OSS example manifests** in `e2e/manifests/`, which double as the
  release-gate smoke fixtures: `grafana` (OIDC + role mapping),
  `audiobookshelf` (OIDC), a directory-backed presentation-only tile,
  `proxywatch` (forward_auth), and `statuspage` (external).
- **Caddy worked example** (`caddy/`): a reference Caddyfile and per-pattern
  snippets (oidc-app, ldap-app, forward-auth, admin-session).
- **e2e mailpit catcher** plus smoke Section H, proving the contact form sends,
  the mail lands, and bad input is rejected.
- **Default-group tile gating.** `OTHALA_DEFAULT_GROUP` closes the external-tile
  gap: every tile gates through a group, and a tile with no explicit
  `access_group` falls back to the default group instead of bypassing the gate.
  The default is auto-appended to the admin group selector but never
  auto-assigned to identities.
- **Adversarial e2e specs** codifying the threat model for the robustness
  harness: consent CSRF tampering, AAL2 bypass, forged sessions, and
  member→admin POST mutations (`e2e/playwright/tests/e`–`h`).

### Changed

- **Renamed to Othala**, deployed at `dag.dunn.dev`. The converged application
  builds and publishes at the registry root as `othala`
  (`registry.gitlab.com/dunn.dev/othala`); the app package is
  `@dunn.dev/othala-portal`.
- **Config exposed, not hidden.** `OTHALA_SMTP_CONNECTION_URI` and
  `OTHALA_CONTACT_RECIPIENT` are explicit load-time params, documented in
  `.env.example` and consumed in the single config module (`lib/config.ts`).
- **Visual-consistency pass.** One house style across every page — unified
  admin navigation, a consistent 1100px page width, a single display heading
  per page, and normalized badge/chip + surface tokens.

### Removed

- **Build-time app catalog.** The Astro Content Collection (`content/apps/`)
  and the static `hydra/clients/` registration are gone, superseded by the
  runtime loaders.
- **The maintainer's private app catalog** moved out of the repo. The shipped
  examples are generic OSS apps; the operator's real manifests live in the
  deployment plane, not here.
- **Non-functional UI** removed in a functionality audit: nothing shown ships
  non-functional. The `/admin/activity` placeholder, the dead "Edit yaml"
  button (now a real source-file label), and the throwaway `/preview` route
  (plus `preview-loader.ts` and `preview-manifests/`) are gone.

### Validation

- Smoke harness green on the QEMU runner (incl. the contact-form
  Section H); 459 portal unit tests; `astro check` and `astro build` clean.

[0.6.1]: https://gitlab.com/dunn.dev/othala/-/releases/v0.6.1
[0.6.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.6.0
[0.5.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.5.0
[0.4.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.4.0
[0.3.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.3.0
[0.2.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.2.0
