# Changelog

All notable changes to Othala are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The git tag is the authoritative version; `portal/package.json` mirrors it.
`docs/STATUS.md` carries the deployed-instance release state.

## [Unreleased]

Security hardening pass (CVP).

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

[0.2.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.2.0
