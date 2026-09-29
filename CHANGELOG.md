# Changelog

All notable changes to Othala are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The git tag is the authoritative version; `portal/package.json` mirrors it.
This CHANGELOG and git tags carry the deployed-instance release state.

## [0.6.4] - 2026-09-29

Session and profile lifecycle: access ends where it should, identity fields apps key on are admin-controlled, and admin accounts cannot lock themselves out.

### Changed

- Password policy rejects any known-breached password and no longer accepts a password when the check cannot be completed.
- Trace spans no longer carry the return_to value.
- Deleting an identity deactivates it and revokes its sessions and app grants first; a failed delete reports the inactive identity.
- Removing a group or changing a role revokes the member's app grants.
- Signing out of an app also ends the portal session.
- An app sign-in is remembered for as long as the portal session lasts.
- The reference edge snippets pass the verified identity id to the upstream and remove the Kratos session cookie from app-bound requests; `.env.example` documents the admin bind hosts.
- Only an administrator can change a username; profile settings show it read-only.
- Saving profile settings ends the account's other sessions.
- `email_verified` reflects only the account's own email address.
- The request form requires a signed-in account; the mail names the account, and the rate limit is per account.
- The error page shows only reasons it recognises.
- Admin accounts keep at least one authenticator app or security key through settings.
- The admin console refuses to deactivate your own identity or the last active admin, and to remove your own last authenticator app or security key.
- Signing out takes a form post with a token bound to the signed-in identity; opening `/auth/logout` shows a confirm button.
- Saving an identity in the admin console keeps stored groups that have no checkbox (role-mapped or not configured); removing one is an explicit tick.
- The reference forward-auth snippet runs its header strip, session check and proxy in a `route` block, so the verified identity id reaches the upstream.
- The portal's `form-action` policy admits the Kratos origin, so signing out works when Kratos is on another host.

## [0.6.3] - 2026-09-29

### Changed

- Signing in to connected apps now completes second-factor verification for
  accounts with one enrolled, and for admin accounts. Admin accounts sign
  in with a passkey or password rather than an emailed code. Granting admin
  requires an enrolled second factor.

## [0.6.2] - 2026-09-26

Quieter health-probe logs, a markdown-sanitizer gap closed, and three
routine dependency majors.

### Changed

- `kratos.yml`/`hydra.yml` set `request_log.disable_for_health: true` on both
  listeners, so health probes stop logging. Hydra's admin listener logs them
  anyway: probe Hydra's public `/health/ready`, as e2e does (smoke A0).
- Base image UBI 9 -> UBI 10; isomorphic-dompurify v4 (jsdom 30); nodemailer
  v10.

### Security

- Education markdown drops `<style>` and form controls.

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

Docs convergence (corpus cut two-thirds, 16 ADRs folded into one DECISIONS.md, gated by a prose-budget ceiling and a whole-index purity scan), a truth pass, admin-triggered invite email (D1), a purity-gate rewrite, CI/test consolidation onto vitest, and six at-a-glance diagrams now live on othala.dunn.dev.

## [0.4.0] - 2026-08-13

Admin-POST and AAL2 step-up fixes, extensible Hydra CORS for browser-SPA clients, the othala.dunn.dev docs site, and a decisions/docs rewrite that stands the project alone from the operator's private deployment.

## [0.3.0] - 2026-07-01

Security hardening pass (CVP), access-model refactor, PII-safe OpenTelemetry tracing, and a portal UX/pristine pass.

## [0.2.0] - 2026-06-04

The convergence release: a breaking move from a build-time app catalog to a runtime manifest model, plus the rename to **Othala** ("Ory for your home").

[0.6.4]: https://gitlab.com/dunn.dev/othala/-/releases/v0.6.4
[0.6.3]: https://gitlab.com/dunn.dev/othala/-/releases/v0.6.3
[0.6.2]: https://gitlab.com/dunn.dev/othala/-/releases/v0.6.2
[0.6.1]: https://gitlab.com/dunn.dev/othala/-/releases/v0.6.1
[0.6.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.6.0
[0.5.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.5.0
[0.4.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.4.0
[0.3.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.3.0
[0.2.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.2.0
