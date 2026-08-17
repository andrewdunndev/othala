# Hardening

How this system is hardened, and why each control sits where it does.
Companion to `SECURITY.md` (scope and reporting) and the repository's dated
adversarial security reviews.

`portal/src/middleware.ts` cites §2 of this page from three places, so that
section is the rationale store for the response-header baseline.

## Posture: the controls ship with the install

Othala is an authentication substrate. It issues the tokens and gates the
access everything downstream trusts, so the controls that keep it safe ship
**with the install** rather than being delegated to a CDN or WAF in front of
it. An edge WAF is a welcome outer layer where one exists, but nothing here
depends on one: where this page names an intrinsic control (response headers,
admin isolation), that control is the load-bearing one.

That reverses an earlier scoping decision on this project: application-layer
abuse resistance (flood, brute-force, hash exhaustion) was once treated as the
operator's edge concern. It is in scope now, and §1 says which parts of it are
actually built.

## Threat model (summary)

Tiers (full detail in the project's adversarial security review):

- **Tier 1 — passive network / CDN:** TLS-terminated; only hostnames leak.
- **Tier 2 — compromised app container:** the attacker tier most controls
  target. Bounded by the pod/network boundary (see *Admin-API isolation*).
- **Tier 3 — compromised admin mailbox:** blocked for admin identities at the
  recovery-gate webhook.
- **Tier 4 — host root:** out of scope; game over.
- **Physical / lost-stolen-shared device:** the dominant *real* threat for a
  family. Covered under *Sessions & lost-device*.

Asset value: family identity + per-app data. Worst case is a privacy breach
across the family, not financial fraud.

## 1. Application-layer abuse resistance

The risks: **email-bomb** (unauthenticated volume against the email-code /
recovery / verification flows floods a family member's inbox), **credential
brute-force** (Kratos has no native account lockout — by Ory's design, throttling
is delegated to the deployment), and **password-hash exhaustion** (every password
attempt runs argon2id at 128 MB; enough concurrent valid-looking attempts can
exhaust host memory — the server's own security parameter becomes a DoS lever).

What is built:

- **Reverse-proxy `rate_limit` on the Kratos browser paths.**
  `caddy/Caddyfile` in this repo carries the shape but is not itself a deploy
  artifact: its header calls it "an integration example for adopters, not a
  drop-in deploy file", and its rate-limit section carries a standing "!!
  BLOCKER — DO NOT DEPLOY THIS CADDYFILE UNTIL THE MODULE IS IN THE IMAGE !!".

  The shape: a `rate_limit` zone keyed on `{remote_host}` at `events 10` /
  `window 1m`, on the matcher `@kratos path /.well-known/ory/*
  /self-service/* /sessions/* /schemas/*`, under a global `order rate_limit
  before basicauth`.

  `rate_limit` comes from the third-party module `mholt/caddy-ratelimit`, so a
  Caddy binary without it compiled in does not degrade — the file records that
  it fails with "unrecognized directive: rate_limit".
- **In-process rate limit on the dashboard request form.** One endpoint is
  rate-limited inside the portal itself. `portal/src/lib/contact.ts` holds a
  sliding-window counter — `const WINDOW_MS = 10 * 60 * 1000` and `const
  MAX_PER_WINDOW = 5`, keyed by `ctx.clientAddress` — and
  `portal/src/pages/api/request.ts` calls it as step 1 of the POST handler
  ("Rate limit first — a flood shouldn't reach validation/SMTP"), answering a
  blocked caller with `429` plus a `Retry-After` hint. Its `hits` Map is
  hard-capped at `HITS_MAP_MAX = 10_000` entries, cleared entirely above that
  bound rather than growing to OOM. It covers the contact
  form and nothing else; the Kratos auth flows are not behind it.
- **Ory flow config.** `code.config.max_submissions` is set explicitly, so a
  flow is invalidated after a bounded number of wrong 6-digit codes rather than
  standing open. Recovery runs `notify_unknown_recipients: false`, which
  declines to confirm to a stranger whether an address is enrolled. Values and
  rationale are ADR 11; the file is byte-vendored, so read ADR 13 before
  editing it.

What is **not** built, stated plainly because the risk is real:

- **No concurrency bound on password hashing.** Nothing caps how many argon2
  operations Kratos will run at once. A `max_conns` cap on the Kratos upstream
  in Caddy would bound the memory-exhaustion lever regardless of source-IP
  diversity, and this repo's `caddy/Caddyfile` sets none.
- **The email-code lifespan outlives its login flow.** The code is valid for
  longer than the login flow that issued it, so a code can arrive still-valid
  against an expired flow. Aligning the two would close it; nothing does today.

## 2. Auth-UI browser hardening

An IdP's login and consent pages are the highest-value clickjacking and
token-leak targets in any deployment. Othala sets a security-header baseline on
**every** response, centralised in the portal middleware:

- `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` — the login and consent
  pages must not be frameable. (Both, for old-browser coverage.)
- `Content-Security-Policy` — the header set on every response is exactly
  `frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action …`.
  **There is no `script-src` and no `default-src`.** That omission is
  deliberate: a strict `script-src` can break the Kratos WebAuthn login
  ceremony, which injects inline `<script>` nodes, and the portal's own inline
  theme/modal scripts. Adding one requires live e2e validation of every auth
  flow, and it is still deferred. So the CSP here is a framing, base-URI, and
  form-target control — not XSS insurance.
- `form-action` is `'self'` plus `https://*.<OTHALA_APEX>` when `OTHALA_APEX` is
  set in the environment, falling back to strict `'self'` when it is not. It
  cannot be `'self'` alone: `form-action` governs a form submission's redirect
  chain, not just its action URL, and an OIDC login's post-login redirect lands
  on the requesting app's own domain.
- `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`,
  `Permissions-Policy` (deny camera/mic/geo), `Cross-Origin-Opener-Policy: same-origin`.
  (`Referrer-Policy` was `no-referrer` until work item #5: Chromium sends
  `Origin: null` on a same-origin form-POST navigation under `no-referrer`,
  which Astro's `checkOrigin` CSRF gate then rejects before app code runs —
  every admin mutation was unreachable. `same-origin` still sends no referrer
  cross-origin — closing the token-leak this section opens with — while
  restoring the same-origin `Origin` header `checkOrigin` needs. See
  `portal/src/middleware.ts`.)
- **No third-party CDN assets.** Fonts are self-hosted under
  `portal/public/fonts/`. Loading them from an external CDN sends the page's
  `Referer` — including the `flow` / `consent_challenge` identifiers — to that
  third party; that was the original reason for the `Referrer-Policy` above.
- **Sanitise rendered markup.** Any operator-authored content rendered via
  `set:html` (e.g. per-app help text via `marked`) is passed through a sanitiser
  (DOMPurify) first. Even operator-authored content gets sanitised, so a widened
  trust boundary later (a CMS, a shared manifest dir) can't become an XSS sink.

## 3. Admin-API isolation & network segmentation

**The core fact:** Ory's Kratos and Hydra **admin APIs are unauthenticated by
design** — Ory's model assumes the *network* is the boundary. So how those admin
ports (`:4434`, `:4445`) are reachable is the single most important deployment
decision.

### The trap: a second network alone does not segment

A listening socket bound to `0.0.0.0` answers on **every** network interface the
container has. Attaching Kratos to a second, internal-only network does **not**
hide `:4434` from the first one; it still answers there. Segmentation needs two
things together: the second network, **and** an admin listener bound to that
network's address so it stops answering anywhere else. A deployment that does
only the first has the appearance of isolation and none of it.

### What the configs require: a bound listener, not just a network

The admin bind address is a required variable rather than a constant.
`kratos/kratos.yml` sets `serve.admin.host` to
`${KRATOS_ADMIN_BIND_HOST}` and `hydra/hydra.yml` sets it to
`${HYDRA_ADMIN_BIND_HOST}`, each under the same in-file note: the admin API is
unauthenticated by design, "so segmented deployments bind it to an address only
the admin-plane network can reach. Single-network deployments (the e2e harness)
use `0.0.0.0`."

Hydra's config adds the floor for the admin port itself: "NEVER expose
publicly."

`scripts/render-config.sh` derives its variable contract from the template —
"every `${NAME}` token found in it must be SET in the environment, else we fail
fast listing the missing NAMES" — so the render cannot proceed without a bind
address. Nothing in this repo checks *which* address was supplied.

Where the portal reaches the Kratos admin API directly, with no mTLS proxy in
between, **network isolation, not client authentication, is the load-bearing
control on that hop** (ADR 03).

**The residual, stated honestly:** an edge proxy attached to the admin-plane
network as well as the edge one segments the admin APIs against every container
outside the auth stack, and does *not* segment them against a compromise of the
edge proxy itself. That is the remaining Tier-2 path.

### Cheap wins alongside it

- **`sslmode=disable` on the Ory → Postgres DSNs.** Both `kratos/kratos.yml`
  and `hydra/hydra.yml` carry `?sslmode=disable` in their `dsn` values. The
  configs treat this as an accepted risk rather than a gap — the OTLP exporter
  note in each file describes its own plaintext hop as the "Same accepted-risk
  posture as the `sslmode=disable` DSN above" — but neither file records the
  DSN's own rationale, and no ADR states one. Don't infer one from this page.
  Both files are byte-vendored: read ADR 13 before editing either.

### Gating the auth surface — no

A tempting question: put the whole entrypoint behind a long password or mTLS?
**You can't** — and the reason is definitional. An IdP exists to serve
*unauthenticated* callers: browsers hitting the login / passkey / email-code flows
before they have a session, and relying-party *servers* doing OAuth2 token
exchange, OIDC discovery, and JWKS fetches. Every OIDC app here is such a server.
A shared basic-auth password or client-cert wall on that surface breaks
passkey-first UX *and* breaks every OAuth2 RP.

`portal/src/lib/admin.ts`'s `requireAdminSession` enforces what
its own header calls the trinity: an active session, an `aal2` assurance level,
and `metadata_admin.admin === true` — checked server-side on every `/admin`
request (ADR 08). An `aal1` session is redirected to the Kratos step-up flow
rather than admitted.

## 4. Secrets handling

- **Ory's own secrets are file-mounted; the portal's come from the process
  environment.** ENV secrets are readable via `/proc/<pid>/environ` to anything
  in the user namespace. Kratos and Hydra read their secrets from their config
  files — the Hydra system secret and the cookie/cipher secrets are `${VAR}`
  tokens that `scripts/render-config.sh` substitutes into the YAML *before* a
  container mounts it, so those values need not be in any process environment.
  The portal's are: `portal/src/server/listen.mjs` reads both
  `process.env.RECOVERY_GATE_SECRET` and `process.env.OTHALA_ADMIN_ENDPOINT_BEARER`
  straight from the environment. Closing that means a tmpfs-backed mount and a
  portal that reads from the path. It is a known gap, not an oversight.
- **The Hydra system secret is non-rotatable** — rotating it invalidates every
  issued token and client secret (a DB-rebuild event; see
  `docs/runbooks/secrets-rotation.md`).
- **Rotation is prepend-a-distinct-entry, never a duplicate slot.** Ory's
  secrets arrays model rotation via distinct entries — the first signs, older
  entries still verify — and Kratos and Hydra both enforce `uniqueItems` on
  them, so a single active secret is a *single-element* array and two identical
  slots is a config error, not a no-op. Runbook:
  `docs/runbooks/cookie-rotation.md`.
- **Entropy:** cookie secrets are `openssl rand -hex 32`; the Kratos cipher
  secret is `openssl rand -hex 16`, i.e. exactly 32 characters
  (`e2e/gen-secrets.sh`). No plaintext secrets in any committed config: the
  `secrets:` blocks of `kratos/kratos.yml` and `hydra/hydra.yml` hold only
  `${VAR}` tokens — `${KRATOS_COOKIE_SECRET_CURRENT}`,
  `${KRATOS_CIPHER_SECRET_CURRENT}`, `${HYDRA_SYSTEM_SECRET}`,
  `${HYDRA_COOKIE_SECRET_CURRENT}` — resolved at render time.

## 5. Container baseline

Othala ships no deployment artifact. The only container-runtime file in the
repository is `e2e/compose.yml`, whose own header calls it "the project's
canonical OSS-facing end-to-end example" of how the stack "stands up on plain
`docker compose` from the published images", and notes that it "doubles as the
CI `e2e` gate". So what follows is not a description of a running deployment: it
is the baseline the project's own example brings up, and the one CI exercises on
every tag.

What that file sets on each long-lived service — postgres, mailpit, Kratos,
Hydra, the othala app, and the `profiles: ["browser"]` Caddy:

- **`security_opt: ["no-new-privileges:true"]`**, on all six. The file's own
  rationale: "safe on all OCI runtimes; prevents any setuid binary inside the
  container from elevating past the container user."
- **`cap_drop: [ALL]`**, on all six, with two documented add-backs. Postgres
  adds CHOWN, DAC_OVERRIDE, FOWNER, SETUID and SETGID because its entrypoint
  chowns PGDATA and setuid-drops to the postgres user before serving; the file
  records that these "are init-time only; postgres holds none of them once it
  has dropped to its unprivileged user." The e2e Caddy adds NET_BIND_SERVICE
  because it binds port 80 inside the container. Kratos, Hydra and the app add
  nothing back — their ports (4433/4434, 4444/4445, 8080/4431) are all above
  1024.

  The drop is load-bearing rather than decorative, and the harness carries the
  scar that proves it: `e2e/validate.sh` chmods the rendered configs to 0644,
  because under `cap_drop: [ALL]` there is no CAP_DAC_OVERRIDE and "A 0600 file
  owned by 1000 is unreadable by 10000 → … kratos-migrate, kratos serve and
  hydra serve all Exit(1)".
- **`read_only: true` plus an explicit `tmpfs`, on four of the six.** Kratos,
  Hydra, the app and the e2e Caddy run with a read-only rootfs, each with a note
  naming what it still writes: Kratos "writes only to /tmp at runtime (temp flow
  files, session state is in postgres)", Hydra "crypto scratch, temp JWK files",
  the Node app `/tmp` scratch, Caddy `/data` + `/config` + `/tmp` for its ACME
  state. Postgres and mailpit **deliberately omit it**, each under a standing
  in-file marker that it must be validated on a real host before being enabled —
  postgres because "Adding `read_only: true` to postgres risks an opaque startup
  failure", mailpit because the path of its sqlite message store is unconfirmed.
  Read-only rootfs is therefore partial here, and the file says so rather than
  implying coverage it does not have.
- **`pids_limit`** on all six: 512 for postgres, Kratos, Hydra and the app; 256
  for mailpit and Caddy.
- **Digest pins on every third-party image.** postgres, mailpit, Kratos, Hydra,
  Caddy and the Playwright base are each `image@sha256:…`, as is the UBI 9 build
  stage in `portal/Containerfile` and every job image in `.gitlab-ci.yml`.
- **A non-root app process.** `portal/Containerfile` ends `USER 1001` after
  copying the build output, and no service in the compose file overrides `user:`
  — each image's own user applies (Kratos and Hydra run as the image's `ory`
  user, uid 10000).

What is **not** set:

- **No memory bound, anywhere.** Not one service declares `mem_limit` or any
  equivalent. §1's password-hash exhaustion lever — argon2id at 128 MB per
  attempt — is therefore unbounded at the container layer as well as at the
  proxy, so nothing in this repository caps it at any layer.
- **No digest pin on the project's own images.** The compose file resolves the
  app as `${AUTH_REGISTRY}:${AUTH_VERSION}`, and `portal/Containerfile`'s runtime
  stage is `FROM …/ci-runtime-node:${CATALOG_VERSION}` — a tag ARG carrying a
  `# renovate:` annotation, not a digest. `renovate.json` disables the native
  dockerfile manager for that image by name so the annotated ARG remains its sole
  tracker, which keeps the tag moving deliberately; it is still a tag.
- **No registry auto-update path, and no user-namespace mapping.** Nothing here
  configures either. Both are properties of whatever runs the images. A runtime
  that pulled new images on a mutable tag would be promoting builds that never
  passed the tag pipeline, whose e2e stage "gates the package + release stages".

## 6. Supply-chain

What is built:

- **An SBOM per tagged image, linked from the release.** `.gitlab-ci.yml`
  includes the shared `container-sbom` component as `sbom-othala`, scanning
  `${CI_REGISTRY_IMAGE}:${CI_COMMIT_TAG}` into `othala-container.sbom.json`, and
  the `release-create` include takes `sbom_job: sbom-othala` so the GitLab
  Release record links it. The pipeline header states the flow: "package
  container-sbom -> syft scan, upload CycloneDX".
- **Reproducible installs from committed lockfiles.** Every install on every
  build path is `npm ci`, never `npm install`: `portal/Containerfile`'s build
  stage, `e2e/Containerfile`'s `npm ci --no-audit --no-fund`, and the
  `test-portal` and `check-portal` jobs' `npm ci --include=dev`. `portal/`,
  `e2e/` and `site/` each commit a `package-lock.json`.
- **Signing, asserted by the pipeline and opted out of exactly once.** The
  pipeline header records the tag flow as "build container-image -> push :TAG +
  :latest + cosign sig". The signing step itself lives in the shared
  `container-image` component rather than in this repository; the only signing
  knob set here is `sign_image: false` on the test-only `build-e2e-tester`, with
  its reason inline — "this is a test-only image, not a shipped artifact."
- **Dependency currency tracked, with the two coupled bumps held back from
  automerge.** `renovate.json` extends the shared preset and adds two
  `automerge: false` rules for pairs that must move together: `@playwright/test`
  with `mcr.microsoft.com/playwright` (the matching Docker tag publishes days
  after the npm release, so an ungated run lands the npm bump alone — it did, on
  two separate versions), and the pipeline-catalog pair of the Containerfile
  `CATALOG_VERSION` ARG with the `.gitlab-ci.yml` component pins (a stale ARG
  breaks the next tag build once the registry GCs the old image tag — it did).
- **A pre-tag gate that refuses to pass on nothing.** `scripts/pre-tag-check.sh`
  runs the CI test, typecheck and build steps locally before a tag under an
  explicit "ANTI-VACUITY CONTRACT": every file-driven step enumerates from `git
  ls-files`, "asserts the set is NON-EMPTY, and calls step_error (never
  step_pass) when it is". Two steps that had been printing PASS over
  directories that no longer existed were found and removed.

What is **not** built:

- **Nothing evaluates the SBOM.** There is no `grype`, `trivy`, `govulncheck` or
  `npm audit` step anywhere in this repository — the e2e image build explicitly
  passes `--no-audit`. A known CVE in a shipped image is recorded in the SBOM and
  fails nothing.
- **Nothing verifies a signature before use.** There is no `cosign verify` step
  here. Verifying the signature before an image is run is a property of whatever
  pulls it, not something this repository enforces.
- **No constraint on dependency install scripts.** Nothing sets `ignore-scripts`
  or otherwise bounds what a package's `postinstall` may do during `npm ci`.

## 7. Sessions & lost-device

The dominant real-world threat for a family is a lost, stolen, or shared device,
not an internet attacker.

- **Session length, and what the admin gate does and does not check.** The Kratos
  session lifespan is the everyday window and is deliberately long, because
  passkey-first daily use should not be miserable. On top of it, `/admin`
  requires an `aal2` session plus the `metadata_admin.admin` marker, both
  re-checked server-side on every request (ADR 08). **It does not check
  freshness.** A freshness computation exists in `portal/src/lib/admin.ts`
  (`isSessionFresh`) and is deliberately *not* wired into the gate; it is
  unit-tested against the day it is. So a browser that satisfied AAL2 at some
  point in the session window still satisfies the admin gate, and the separate
  15-minute privileged window applies to the Kratos **settings** flow
  (credential changes), not to `/admin`. Wiring freshness in is the open
  hardening item here.
- **Eviction must remove credentials, not just sessions.** `revokeSubject` /
  "force re-login" terminates active sessions — it does **not** delete enrolled
  credentials. A thief who gets a brief session can enrol *their own* passkey;
  that credential survives the revoke and a password reset, and they log straight
  back in. So the lost-device procedure is: audit the identity's credentials →
  delete the affected credential **type** → *then* revoke. Note the unit: the
  Kratos admin API has no per-passkey removal, so deleting `webauthn` or
  `passkey` evicts **every** credential of that kind for that identity, the
  user's good ones included. That is why the procedure ends with re-enrolment
  (ADR 14) rather than with a surgical delete. See
  `docs/runbooks/admin-recovery.md`.
- **No notification on email-code login.** A "new sign-in via email code" message
  to a secondary address would collapse the detection window from "whenever the
  victim notices" to minutes. It is not built; the detection window is currently
  however long it takes someone to notice.

## What stays the operator's responsibility

- Device-layer controls (screen lock, per-app lock, remote wipe) — outside
  Othala's enforcement perimeter but the real mitigation for lost devices.
- Host hardening (bootc/immutable base, ZFS, rootless Podman) — the secondary
  boundary under the pod/network boundary.
- Volumetric L3–L4 DDoS — needs upstream capacity to absorb; an edge concern.
- Backups & their restore correctness across Hydra's encryption-at-rest.
