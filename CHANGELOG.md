# Changelog

All notable changes to Othala are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The git tag is the authoritative version; `portal/package.json` mirrors it.

## [Unreleased]

### Fixed

- A manifest gate flag (`skip_access_check`, `skip_consent`, `backchannel_logout_session_required`, `emit_groups_claim`) must be `true` or `false`; any other value, such as the string `no`, quarantines the file and `manifest-lint` reports it. Before, a non-empty string opened the app to every member.
- An admin save ends the member's app sign-ins whenever their role overrides change in any way (added, changed or removed) or a group is removed; before, a newly added override, such as a demotion kept alongside a shared group, left their old tokens valid. A group addition ends nothing.
- An admin save no longer drops a stored role override for an app with no served manifest (a retired app, a manifest with a mistake, or an unreadable apps directory); the person page lists them under "Overrides for apps not shown" and removes one only on an explicit click.
- An admin save carries `admin`, the picture and passkey names from the identity as it stands when the write happens, so a save racing a revoke-admin no longer restores the marker.
- A stored role override naming a role the app's manifest no longer declares now resolves to the app's lowest declared role instead of falling back to the group-mapped role, and the person page flags it. Rename a role and anyone held back by an override stays held back.
- A password change now also ends the member's app sign-ins and refresh tokens: `kratos/kratos.yml` gains a non-interrupting `settings.after.password` web hook to `/admin/revoke-grants`, authenticated like the other hooks. Deployers who vendor `kratos.yml` and `contract/kratos.schema.json` take both.
- Editing a manifest's access-relevant fields (access groups, `group_role_map`, roles and their `claim_emit`, `emit_groups_claim`, scopes, `skip_access_check`) ends that app's existing sign-ins and refresh tokens for everyone on the next reconcile; before, they kept their old claims for up to 30 days. The fingerprint lives in the Hydra client's metadata. A client without one is baselined, not revoked.
- A Hydra client othala registered whose manifest file is gone has its grants ended once and is marked retired in its metadata. This is skipped while any manifest is quarantined, when none is served, or when the apps directory is unreadable. No client is ever deleted.

## [0.18.0] - 2026-11-11

### Added

- A member picture, set from the settings page or by a household admin on the user page, emitted as the OIDC `picture` claim (ID token and userinfo) under the `profile` scope. It is stored in `metadata_admin.avatar` (PNG, JPEG or WebP, up to 64 KiB) and served without a session at `/avatar/<identity>/<hash>`, so relying parties can fetch it server-side. No schema or Ory config change.
- Before saving, the browser lets the member position and zoom the picture (drag, slider, pinch or keyboard) and crops it to 256x256; without scripts it is a plain upload, checked by the server.
- The picture, or the member's initial, shows on the home greeting, the admin people list and the admin user page.

## [0.17.0] - 2026-11-07

### Added

- Optional `KRATOS_COOKIE_SECRET_PREVIOUS`, `KRATOS_CIPHER_SECRET_PREVIOUS`, `HYDRA_SYSTEM_SECRET_PREVIOUS` and `HYDRA_COOKIE_SECRET_PREVIOUS` render as the second entry of each Ory secret list, so a rotation keeps members signed in and Hydra's database intact. `gen-secrets` mints Kratos cookie secrets at 32 characters.

### Fixed

- DEPLOY no longer asks for `isolate=true` under rootless podman: `internal: true` alone keeps the edge off the admin bind addresses (measured on podman 5.8 and 6, rootful and rootless), and podman 5.8 or later is required.
- Cookie rotation and upgrade steps recreate render, kratos, hydra, othala and caddy (`restart` and plain `up -d` left old config running), and the `docker run` mounts carry `:ro,z` for SELinux hosts.
- Runbooks and config comments match Ory v26.2.0: cookie, cipher and Hydra system secrets accept `[new, old]` lists, the cipher secret is 32 characters, and the admin-marker, readiness, registrar and consent-reset steps use commands that work in the compose deployment.
- `/readyz` also fails while the registrar's last reconcile failed, and a SIGHUP during a reconcile queues one rerun instead of being dropped.
- A remembered login lasts as long as the Kratos session's own expiry; the hardcoded 720h fallback is gone.
- The identity schema no longer carries a `metadata_admin` block; Kratos validates `traits` only and the portal enforces the marker.
- Documentation cut to what a stranger or operator needs: DECISIONS is a ruling list, the Golden path guide and `hydra/README.md` are folded into DEPLOY, DECISIONS and the per-app guide, the recovery-session statements are corrected, and the hardening guide no longer says nothing evaluates the SBOM (CI runs an OSV verdict over it).

### Changed

- Portal tracing moves to OpenTelemetry JS 3 (`@opentelemetry/sdk-trace` replaces the deprecated `sdk-trace-base`); `OTHALA_OTLP_ENDPOINT` and the exported spans are unchanged.
- The GitHub release job runs in its own `github-release` environment, and `check-portal` installs dependencies without lifecycle scripts.

### Removed

- The root and portal Makefiles, and the prose-budget and check-count gates in `scripts/check-purity.sh`.

## [0.16.1] - 2026-10-18

### Fixed

- deploy/example runs the release image. The 0.16.0 tag was never published because its pipeline stopped on this pin.

## [0.16.0] - 2026-10-18

### Config changes

Contract:

- `contract/` pins what the portal depends on in an Ory config. `node dist/server/config.mjs check-ory` validates a deployment's own finished files against it. A deployment that renders its configs needs no change.

Reference:

- The OTLP endpoint is quoted in the `tracing` blocks of `kratos.yml` and `hydra.yml`. Optional: `git diff v0.15.0..<tag> -- kratos hydra`.

### Fixed

- Identity headers with underscores in their names are dropped at the edge.
- The device verify rate limit also matches a trailing path.
- Render refuses more line-break characters in values and quotes the OTLP endpoint.
- A failed render clears the earlier output.

## [0.15.0] - 2026-10-12

The image carries the Ory and edge policy and renders it from the deployment's env and content tree at `/etc/othala`; one command replaces the shell renderer.

### Added

- `node dist/server/config.mjs render` renders `kratos.yml`, `hydra.yml` and the courier templates from env, and copies the identity schema and recovery-gate hook beside them. It refuses an unset or blank secret, any `${` left in the output and malformed YAML, and writes owner-only files.
- `check` validates the non-secret values offline; `gen-secrets` prints fresh values for every secret except the SMTP URI.
- `check` also validates the content tree offline: env names, the layout, manifests, sidecars, `groups.yaml` and courier override names. Every failure names the file or variable and the fix.
- A deployment overrides a courier template with `courier/<name>.gotmpl` under the content root; the render merges it over the shipped default of the same name. An override may name only `${OTHALA_APEX}`, `${OTHALA_INSTANCE_NAME}` and `${OTHALA_PUBLIC_URL}`.
- `gen-secrets --content <dir>` also mints a `<CLIENT_ID>_CLIENT_SECRET` for each confidential OIDC manifest.
- `render` also writes `/run/othala/caddy/othala.caddy` with the public URL written in. It holds three snippets, each one `route` block: `othala-routes` (every route on the public host, with the `othala_device` and `othala_selfservice` rate-limit zones), `othala-forward-auth <host> <port> <group>` and `othala-oidc-app <host> <port>`.
- `deploy/example/`: a compose deployment (the render one-shot, both migrate jobs, Kratos, Hydra, the portal, Caddy and Postgres, with the admin listeners on an internal network), `othala.env.example`, a site Caddyfile and sample content. e2e runs it, with a test-only overlay outside the contract.
- `othala-forward-auth` answers a 403 or 503 in place with a short HTML page; only a 401 redirects to login, with the requested path and query escaped into `return_to`. Every snippet strips client-supplied identity headers first, by family (`Remote-*`, `X-Remote-*`, `X-Auth-Request-*` and others), and `othala-routes` hands every upstream `{client_ip}` as `X-Forwarded-For`.

### Changed

- `check` and `render` refuse an `OTHALA_PUBLIC_URL` that is not a lowercase origin (`scheme://host[:port]`, with no path or trailing slash).
- Content moves to `/etc/othala`: manifests and their `.md` and `.svg` sidecars, `requirements/` and `NOTICE` in `apps/`, and `groups.yaml` at the root. `/etc/portal/manifests` is no longer read.
- A retired env name, or an `OTHALA_*` name othala does not read, stops the portal at boot and fails `check` and `render`, naming the fix. The table is `RETIRED_NAMES` in `portal/src/lib/env-names.ts`.
- `npm run lint:manifests` and `manifest-lint.mjs` take the content root and fail on a BLOCK finding.
- The render empties each output directory in place, also when it refuses, and the image carries `/run/othala/{kratos,hydra,caddy}` owned by uid 10000, so each can be a fresh named volume.
- The `:latest` image tag and its signature move only on a release tag, no longer on every push to main.

### Removed

- `scripts/render-config.sh`. The TS render produces the same bytes for the same inputs.
- `caddy/Caddyfile` and `caddy/snippets/`, replaced by `caddy/othala.caddy`. The snippets no longer carry `tls { dns cloudflare }`.
- `e2e/gen-secrets.sh`: use `gen-secrets`.

### Fixed

- Opening Admin from a session that needed a second factor asked for it, then landed on a not-found page. It now returns to the admin page.

### Deployment changes

In this order, for an existing deployment; [`deploy/example/`](deploy/example/) is the end state.

1. Move your manifests into `apps/` under a content root (`git mv <manifests>/* <content>/apps/`), with `groups.yaml` at the root. Keep a reworded mail there as `courier/<name>.gotmpl`, named after the shipped template it replaces (e.g. `courier/login_code.subject.gotmpl`).
2. Run `node dist/server/config.mjs check --content <dir>` with the non-secret env. Delete every name it reports as retired (`MANIFEST_DIR` is one: under `astro dev` use `CONTENT_DIR`), and write `OTHALA_PUBLIC_URL` as a bare lowercase origin. Keep this check in CI after every edit to `apps/`: the render checks only env names and `courier/`, so a bad app sidelines that app and never stops sign-in.
3. Add the render one-shot: `node dist/server/config.mjs render` from the othala image at the portal's digest, as uid 10000 (the Kratos image's uid; its files are 0600), and run Hydra and its migration as uid 10000 too (its image defaults to nonroot), with the portal's env, every secret and the content root. It now also requires `POSTGRES_PASSWORD` and `CSRF_SECRET` and refuses a blank secret; `gen-secrets` mints each `<CLIENT_ID>_CLIENT_SECRET`.
4. Mount its `/run/othala/kratos`, `/run/othala/hydra` and `/run/othala/caddy` read-only at `/etc/config/kratos`, `/etc/config/hydra` and `/etc/caddy/othala`, and order Kratos, Hydra, both migrate units and Caddy after it. Mount the content root read-only at `/etc/othala` on the portal and the render, in place of `/etc/portal/manifests`.
5. Cut your Caddyfile to the imports and what is yours, as in `deploy/example/Caddyfile`: site addresses, TLS and the DNS provider in the site blocks; `trusted_proxies`, `proxy_protocol` and listeners in the global options. Delete your copied routes, snippets and their `tls`, and your global `order rate_limit` unless your own blocks use `rate_limit` outside a `route`. Your Caddy build needs `caddy-ratelimit` and a DNS module.
6. Behind a load balancer, keep `trusted_proxies_strict` (or a `client_ip_headers` header the balancer overwrites): both rate-limit zones, `othala_device` and `othala_selfservice`, key on `{client_ip}`. Zones you named differently start from zero, which is harmless.
7. Delete your vendored Ory files, courier templates, renderer and Caddy snippets, any drift check over them, and every env var on Kratos and Hydra.

## [0.14.0] - 2026-10-11

The home page lists every app with its full description, in calm sections.

### Changed

- App tiles are rows with the logo, the name and the full description, with no truncation. They sit in two columns on wider screens and one on phones.
- Sections have real headings, and each tile has a labelled Guide button.
- Apps without a logo show initials on a monogram plate. Single-colour logos invert in dark mode.
- The guide dialog shows the app's address, which the tile no longer carries.
- Astro 7.3.6 refuses cross-site form posts from the `Sec-Fetch-Site` header first, and the CSRF tests now send real cross-site headers. Playwright moves to 1.64 and OpenTelemetry to 0.223.

### Deployment changes

- None: image bump only.

## [0.13.3] - 2026-10-10

App logos now live beside each manifest, and passkeys carry a clearer name.

### Added

- App logos are served from `<stem>.svg` files beside each `<stem>.yaml` manifest. The image ships no app logos.

### Changed

- Passkey and security-key names read "<instance name> Single Sign-On". The relying-party id is unchanged, so existing passkeys keep working; saved items keep their old label until renamed.
- The web app manifest's name follows `OTHALA_INSTANCE_NAME`.
- The consent screen shows the monogram only.
- Documentation is shorter across the README, architecture, decisions, security and guides.

### Removed

- The `icon_slug` and `icon_fallback` manifest fields are retired: ignored at serve time and rejected by manifest-lint. The bundled icon set is removed.

### Security
- A logo is served only to a signed-in member who can see that tile, sandboxed (`Content-Security-Policy: sandbox`, `nosniff`, private cache). Every other request gets the same 404.

- The cookie-rotation runbook now states the shipped single-slot behavior: rotation signs every member out. The secret-rotation and backup runbooks now say `secrets.system` encrypts Hydra's signing keys and session data, while client secrets are hashed.

### Deployment changes

- Put `<stem>.svg` beside each `<stem>.yaml` in the manifest directory (stem = the manifest filename, the same key as `<stem>.md`). At most 32 KiB, with an `<svg>` root.
- Remove `icon_slug` and `icon_fallback` from your manifests.
- Copy `*.svg` alongside `*.yaml` and `*.md` into the mounted manifest directory, and do not prune them.
- Re-vendor `kratos/kratos.yml`.
- No environment changes.

## [0.13.2] - 2026-10-09

Two more app tiles get their real logos.

### Changed

- Two more app tiles show the projects' real logos, and two unused icons are removed.

## [0.13.1] - 2026-10-09

Enrollment is easier to follow, and app tiles show the real software logos.

### Changed

- TOTP enrollment shows the setup key as text beside the QR code, with no click to reveal.
- The setup-link result leads with **Copy message** (link and code together). **Copy link** and **Copy code** sit beside it and copy only what they say.
- When an identity has no password yet, the settings password panel is open on load, so a password manager finds the field without a click.
- App tiles use the projects' real logos instead of hand-drawn plates, and unused icons are removed. A tile whose icon slug no longer resolves shows its monogram. `portal/public/icons/NOTICE` credits each source and license.

## [0.13.0] - 2026-10-08

Apps without a secret can sign in, one bad app file no longer takes the rest down, and devices without a browser can sign in with a code.

### Added

- Public clients: an app manifest can register a client without a secret.
- Device authorization grant (RFC 8628) for devices without a browser. The person enters the code on the portal, signs in, and confirms a screen that shows the same code, so a link carrying someone else's code is caught.
- Device logins need a second factor. A passkey-only identity is refused, because Kratos counts a passkey as aal1.

### Changed

- An invalid app manifest is quarantined: it is dropped with a logged reason and its app is refused at login and consent, while the other apps keep serving. Before, one bad file failed the whole set. A quarantined app's Hydra client keeps its refresh tokens and its client_credentials grant working until the manifest is fixed or the client is deleted from Hydra.
- Consumers re-vendor `hydra/hydra.yml`, which now enables the device grant and pins the user-code lifetime.
- Consumers add the device routes to their Caddyfile and the `othala_device` rate-limit zone for `/oauth2/device/auth` and `/device/verify`; see `caddy/Caddyfile`.

### Security

- Accepted risk: a denied or refused device code answers `authorization_pending` to the device's poll until the code expires.

## [0.12.0] - 2026-10-03

Emails name the household, the portal runs on Node 24, Kratos and Hydra updates arrive the day they ship, and code that served old shapes is gone.

### Added

- Recovery, sign-in code and email-verification emails name the household, say where to enter the code and how long it lasts, and end with a warning not to share it.

### Changed

- The portal builds and runs on Node 24 LTS.
- Admins invite a person with the setup link only.
- ID-token claims are always limited to the scopes the app was granted.
- `oidc.client_id` must match `^[a-z][a-z0-9]*$`.
- Kratos and Hydra updates are proposed the day they are released, as one reviewed change.
- Deployers render and mount the email templates in `kratos/courier/` with `scripts/render-config.sh`, next to `kratos.yml`. Kratos reads a template once, so a re-render needs a Kratos restart.

### Removed

- The "Email a code instead" invite. Its code could not be redeemed, because Kratos binds a recovery code to the flow that sent it.
- `presentation.access_group`. Use `presentation.access`, a list. A manifest without it gets no access. A manifest without an `oidc:` block is rejected as invalid.
- The `admin` identity group. Household admin is the admin marker only.

## [0.11.0] - 2026-10-03

Signing out and removing access now also ends app sign-ins, apps that ask for a fresh sign-in get one, and people with elevated app roles keep a second factor.

### Changed

- Signing out of the portal also ends your app sign-ins and app access on every device. Apps with a back-channel logout address are told at once; other apps keep their own session until it expires.
- Removing someone's groups, roles or admin marker now also ends their app sign-ins on every device, not only their app access. They stay signed in to the portal.
- People who hold a role above an app's entry level keep at least one authenticator app or security key through their settings page, as admins do.
- Settings tells an admin with one security key and no authenticator app how to add a second key.
- Expired-page and code messages say how long codes last and cover replaced pages.
- A skip-to-content link, and 44px header links.

### Fixed

- Apps that ask for a fresh sign-in (`prompt=login`) or a maximum sign-in age (`max_age`) get one: an older portal session goes through a fresh sign-in first. A `max_age` under 30 seconds is treated as 30 seconds.
- Kratos and Hydra calls from the portal, and outgoing mail, time out instead of hanging a request.

## [0.10.3] - 2026-10-02

Second-factor and sign-out rules for elevated app roles, a group-aware forward-auth snippet, and clearer errors and logs.

### Changed

- Giving someone an app role above the app's entry level now requires them to have an authenticator app or security key first, as making them an admin already does. This holds when adding a person and when editing one. People who already hold such a role can still be edited or lowered.
- An admin cannot remove the last authenticator app or security key of someone who holds such a role.
- Removing another person's authenticator app, security key or backup codes also signs them out everywhere. The lost-device runbook no longer has a separate sign-out step.
- The admin audit log records person creation (`create-user`). A write that landed but whose follow-up step failed is recorded as `partial` instead of `refused` or `ok`, and an admin who gives up their own access is told if their app grants could not be revoked.
- The reference `forward-auth` snippet calls the portal's `/api/forward-auth` and takes a third argument, the required group. A signed-in member outside the group gets 403. Copies of the snippet need the new argument.
- Upstream failures (Kratos, Hydra) in sign-in, consent and forward-auth are logged to stderr with the failing step. Responses are unchanged.
- Code-entry screens remind people to check spam or junk. An admin's page points to the admin-recovery runbook.
- The copy button in app guides is a full-size tap target.
- `SECURITY.md` lists the accepted risk for members with no second factor.

### Fixed

- A Kratos outage shows "Back in a moment" instead of asking people to sign in again.
- `@opentelemetry/sdk-trace-base` is declared as a direct dependency. It was already installed.

### Removed

- The `/admin/activity` redirect stub. It now returns 404.

## [0.10.2] - 2026-10-01

Internal simplification. No behavior change.

### Changed

- The server entry is TypeScript, bundled like the other server entries. `dist/server/listen.mjs` and `npm start` are unchanged.
- Every Kratos hook checks its bearer through one helper.
- CI type-checks every TypeScript file: portal, e2e and site.

## [0.10.1] - 2026-10-01

A readiness check that reads its dependencies, an audit line per admin action, and one access decision.

### Changed

- `/readyz` on the admin listener checks Kratos and Hydra readiness. It answers 503 and names the dependency that is not ready. `/healthz` stays liveness only.
- App sign-in, forward-auth, admin pages and emailed-code sessions are decided by one function over one parsed identity. The access rules are unchanged.
- `DEPLOY.md`: verify the image signature with cosign before pinning, and pin by tag and digest. Take a `pg_dump` before any deploy that changes an Ory pin; rolling back across that change means restoring it.

### Added

- Each admin action writes one JSON line to stdout: `event`, `action`, `actor`, `target` and `result`, with identity ids only.
- CI fails on a detected secret or an untrackable image pin, and runs the manifest lint.

## [0.10.0] - 2026-10-01

An apps-first home with setup guides, and fewer env vars.

### Added

- The signed-in home is an apps-first tile grid with a top bar for account actions.
- Apps can carry a setup guide and `presentation.requires` prerequisites defined under `requirements/`; a tile shows readiness.
- `manifest-lint` warns on an undefined `presentation.requires` name.
- Account settings groups sign-in, two-step, recovery and profile into cards, with named passkeys and in-place enrollment.

### Removed

Delete each from the deploy environment.

- `OTHALA_DEFAULT_SCHEMA_ID`: Kratos defaults.
- `OTHALA_WEBAUTHN_RP_ID`, `OTHALA_WEBAUTHN_RP_ORIGINS`: `kratos.yml` uses `OTHALA_APEX` and `OTHALA_PUBLIC_URL`.
- `OTHALA_SMTP_FROM_ADDRESS`: mail comes from `noreply@<OTHALA_APEX>`.
- `OTHALA_SITE_NAME`: `OTHALA_INSTANCE_NAME` is the brand name, now required.
- `OTHALA_ADMIN_CONTACT`: the dashboard says "your administrator".
- `OTHALA_DEFAULT_GROUP`, `OTHALA_IDENTITY_GROUPS`: fixed at `admin` and `everyone`.
- `OTHALA_ADMIN_FRESHNESS_HOURS`: step-up is 1h.
- `OTHALA_HIBP_ENABLED`, `OTHALA_PASSWORD_MIN_LENGTH`: breach check on, minimum 12.
- `OTHALA_CORS_ALLOWED_ORIGINS`: Hydra allows `OTHALA_PUBLIC_URL`.
- `OTHALA_PUBLIC_HOST`: the Caddyfile uses `OTHALA_PUBLIC_URL`.
- `OTHALA_OTLP_PROVIDER`, `OTHALA_OTLP_ENVIRONMENT`, `OTEL_*`, `OTLP_INGEST_TOKEN`: use `OTHALA_OTLP_ENDPOINT`.
- `KRATOS_PUBLIC_URL`, `HYDRA_PUBLIC_URL`, `KRATOS_ADMIN_URL`, `HYDRA_ADMIN_URL`, `KRATOS_ADMIN_TOKEN` and `HYDRA_ADMIN_TOKEN`: fixed at `kratos:4433`, `kratos:4434`, `hydra:4445`, no bearer.
- `ADMIN_HOST`: renamed `PORTAL_ADMIN_BIND_HOST`, required in production.
- `KRATOS_PG_HOST`, `HYDRA_PG_HOST`, `KRATOS_ADMIN_HOST` and `CONSENT_HOST`: hosts are `postgres`, `kratos`, `othala`.
- `MANIFEST_DIR` (production reads `/etc/portal/manifests`), `PORT`, `HOST`, `ADMIN_PORT`, `PORTAL_LOGIN_URL` and `PORTAL_CONSENT_URL`: fixed.
- `SMTP_USER`, `SMTP_PASS`, `ACME_EMAIL`, Kratos and Hydra `DSN`: credentials ride in `OTHALA_SMTP_CONNECTION_URI` and `dsn`.

### Changed

- Production needs `OTHALA_INSTANCE_NAME`, `OTHALA_CONTACT_RECIPIENT` and `OTHALA_SMTP_CONNECTION_URI`.
- Only a password change signs out other sessions; passkey, key, app and backup-code changes keep them.
- Kratos and Hydra trace with `OTHALA_OTLP_ENDPOINT`.
- Kratos login flow lifespan is 1h, up from 10m.
- Kratos public CORS is off.
- Caddy `othala_selfservice` limit is 30/min, up from 10.
- `kratos.yml` and `hydra.yml` drop keys restating upstream defaults.
- The e2e suite creates an identity through the admin form and always runs the Caddy edge.

### Fixed

- `/admin/users/new` creates the identity email-verified (`email_verified: true` in the id_token).

## [0.8.0] - 2026-09-30

Apps receive only the groups they bind, privileged roles sign in at aal2, and revoking a person reaches apps by back-channel logout.

### Changed

- An app's `groups` claim carries only the groups its manifest binds (`presentation.access` and `group_role_map` keys) plus its role's `claim_emit`; identity groups and other apps' groups are no longer sent.
- An identity that resolves to a role above an app's entry role signs in to apps and forward-auth edges at aal2, as admin-marked identities already do.
- While no manifest set has loaded, forward-auth answers 503 to an aal1 session.
- The step-up notice for an account without a second factor points to Settings to enrol one.
- Force re-login, delete and sign out everywhere revoke each Hydra login session by id, so apps with a `backchannel_logout_uri` receive a logout token.
- Consent is no longer remembered in Hydra; the manifest's `skip_consent` decides whether the grant screen is shown.
- Refresh tokens issued before 0.8.0 keep their claims until their consent sessions are revoked; revoke consent for every subject once after deploying.

## [0.7.1] - 2026-09-30

Release hardening: rate limits key on the real client, and release jobs wait for e2e.

### Changed

- Self-service rate limits key on the client address, trusting `X-Forwarded-For` only from private-range proxies.
- The SBOM and release jobs run only after e2e passes.
- Pipeline components pin to 4.8.0, the reference docs to `v0.6.0`, and the portal runtime image to a digest.
- Leftover source-comment headers are trimmed, and the unused `axe-core` e2e dependency is removed.
- Renovate: lock file maintenance, and the `ubi10/nodejs-22` 10.2 image digest.

## [0.7.0] - 2026-09-30

Fewer moving parts: one registration lane, one Kratos client, one logout path.

### Changed

- Profile changes need a sign-in from the last 5 minutes (was 15).
- An account with a passkey or password changes its email or recovery email only from a session whose newest sign-in used a passkey or password; the profile hook is now `/admin/profile-gate`.
- Signing in to an app after another account signed out of the shared browser starts a fresh app sign-in; a sign-out an app did not start goes through the portal's own sign-out.
- Every state-changing portal form carries a token bound to its action; the portal refuses to start without a `CSRF_SECRET` of at least 32 bytes.
- Client registration runs only in the portal, on boot; the one-shot registration command, its compose service and its docs are gone.
- The portal image builds on `ci-runtime-node` 4.8.0.
- Source comments and docs are trimmed, and the tracked-prose ceiling drops to 153,000 bytes.

### Removed

- `POST /admin/revoke-user` and `OTHALA_ADMIN_ENDPOINT_BEARER`; the admin console covers the same ground.
- `HYDRA_PAIRWISE_SALT` and the Hydra pairwise block.
- LDAP remnants: the `ldap-app` snippet, the lab `glauth.cfg` and `filedrop` fixture, the LDAP bridge settings, and the `ldap` and `oidc+ldap` tile kinds.
- The `admin-session` snippet, `scripts/pre-tag-check.sh`, the two CI jobs that compared mirrored copies, and the `is_admin` and `groups` fields of the gate webhook body; the gates read the admin API.

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

[0.7.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.7.0
[0.6.4]: https://gitlab.com/dunn.dev/othala/-/releases/v0.6.4
[0.6.3]: https://gitlab.com/dunn.dev/othala/-/releases/v0.6.3
[0.6.2]: https://gitlab.com/dunn.dev/othala/-/releases/v0.6.2
[0.6.1]: https://gitlab.com/dunn.dev/othala/-/releases/v0.6.1
[0.6.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.6.0
[0.5.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.5.0
[0.4.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.4.0
[0.3.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.3.0
[0.2.0]: https://gitlab.com/dunn.dev/othala/-/releases/v0.2.0
