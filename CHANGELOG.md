# Changelog

All notable changes to Othala are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The git tag is the authoritative version; `portal/package.json` mirrors it.
This CHANGELOG and git tags carry the deployed-instance release state.

## [Unreleased]

## [0.3.0] - 2026-07-01

Security hardening pass (CVP), access-model refactor, PII-safe
OpenTelemetry tracing, and a portal UX/pristine pass.

### Added (post-rc, folded at tag time)

- **Portal UX pass**: passkey-first login copy (Face ID / Touch ID), a
  dismissible first-run passkey-enrollment nudge, legacy relabeling in
  settings (security key = legacy 2FA; password = legacy: Jellyfin/AppleTV),
  in-flight disable-on-submit feedback on admin forms, and a11y/design-system
  purity fixes (contrast, nested landmarks, raw-color removal, chip/badge
  unification, mobile reflow).
- Per-node validation messages rendered in FlowNodes + login step-2/TOTP.
- Admin-recovery hardening: real recovery-refusal test; `::` and `""` admin
  wildcards blocked (T2-N/T2-O).
- Admin recovery switched to `createRecoveryCodeForIdentity` (Kratos
  v26.2.0+ compatibility).
- ADR set expanded: migration join-key/durable-key (0004 revisions),
  capability groups, first-party skip-consent; docs decoupled from the
  shelved LDAP bridge.

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
  per-app forward-auth gating for Gather, Open WebUI, and Observe tiles.
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
- **Open WebUI OIDC manifest** (`access-llm` gate) and **Gather forward-auth
  tile** (`access-gather` gate) as shipped example manifests.
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
  `audiobookshelf` (OIDC), `jellyfin` (LDAP via the bridge), `proxywatch`
  (forward_auth), and `statuspage` (external).
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

- Smoke harness green on the carmine QEMU runner (incl. the contact-form
  Section H); 459 portal unit tests; `astro check` and `astro build` clean.

[0.3.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.3.0
[0.2.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.2.0
