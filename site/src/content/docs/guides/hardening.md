# Hardening

How this instance is hardened, and why each control sits where it does.
Companion to `SECURITY.md` (scope and reporting) and the repository's dated
adversarial security reviews.

`portal/src/middleware.ts` cites §2 of this page from three places, so that
section is the rationale store for the response-header baseline: read it before
changing a header.

## Posture: the controls ship with the install

Othala is an authentication substrate. It issues the tokens and gates the
access everything downstream trusts, so the controls that keep it safe ship
**with the install** rather than being delegated to a CDN or WAF in front of
it. An edge WAF is a welcome outer layer where one exists, but nothing here
depends on one: where this page names an intrinsic control (rate-limit,
response headers, admin isolation), that control is the load-bearing one.

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

- **Reverse-proxy `rate_limit` on `/self-service/*`.** `caddy/Caddyfile` in this
  repo rate-limits the Kratos browser endpoints per client IP, keyed on
  `{remote_host}`. The X-Forwarded-For overwrite next to it is part of the same
  control: `@astrojs/node` resolves `clientAddress` from the leftmost XFF entry,
  so without overwriting the header an attacker prepends a fresh fake IP per
  request and lands in a new bucket every time. If Caddy is ever fronted by an
  L4 or SNI-passthrough hop, `{remote_host}` becomes that hop and the per-client
  key collapses to one global bucket; the fix is PROXY protocol plus
  `trusted_proxies` at that hop, not a CDN-injected header, which would tie the
  control to one provider.
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
  diversity, and no shipped or deployed Caddyfile sets one. The rate-limit above
  is the only thing standing in front of it, and rate-limiting is per-IP where
  this lever is not.
- **The email-code lifespan outlives its login flow.** The code is valid for
  longer than the login flow that issued it, so a code can arrive still-valid
  against an expired flow. Aligning the two would close it; nothing does today.

## 2. Auth-UI browser hardening

An IdP's login and consent pages are the highest-value clickjacking and
token-leak targets in any deployment. Othala sets a security-header baseline on
**every** response, centralised in the portal middleware:

- `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` — the login and consent
  pages must not be frameable. (Both, for old-browser coverage.)
- `Content-Security-Policy` — `default-src 'self'`; inline scripts carry a
  per-request nonce; `object-src 'none'`; `base-uri 'self'`; `form-action 'self'`.
  CSP is also the standing insurance against any future XSS regression: with no
  CSP, a single mistaken `set:html` on a user-controlled field would execute in an
  admin's session. With it, the blast radius is contained.
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`,
  `Permissions-Policy` (deny camera/mic/geo), `Cross-Origin-Opener-Policy: same-origin`.
  (`Referrer-Policy` was `no-referrer` until work item #5: Chromium sends
  `Origin: null` on a same-origin form-POST navigation under `no-referrer`,
  which Astro's `checkOrigin` CSRF gate then rejects before app code runs —
  every admin mutation was unreachable. `same-origin` still sends no referrer
  cross-origin — closing the token-leak this section opens with — while
  restoring the same-origin `Origin` header `checkOrigin` needs. See
  `portal/src/middleware.ts`.)
- **No third-party CDN assets.** Fonts and all static assets are self-hosted.
  Loading fonts from an external CDN sends the page's `Referer` — including the
  `flow` / `consent_challenge` identifiers — to that third party, and blocks a
  strict `default-src 'self'` CSP. Self-host everything the auth UI needs.
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

### What this instance does

Two Podman networks, not one. An internal network carries the admin APIs and
Postgres and is created `Internal=true` (no external routing) with
`isolate=true`; a separate edge network carries the TLS edge to the public
listeners. Ory's admin listener is bound to the container's internal-network
address rather than `0.0.0.0`, and the admin ports are never `PublishPort`ed to
the host. The portal reaches the Kratos admin API as a direct same-host hop
across the internal network, with no mTLS proxy in between: **network isolation,
not client authentication, is the load-bearing control there** (ADR 03).

None of those three properties is documentation-enforced. They are asserted by
the deploy plane's own contract gate, which fails the deploy if the admin port
gains a `PublishPort`, if the admin bind host is anything but the internal
address, or if the portal's admin URL stops pointing at the direct hop. That
gate, not this page, is the authority on the values.

**The residual, stated honestly:** the edge proxy is attached to the internal
network as well as the edge one, so this segments the admin APIs against every
container outside the auth stack, and does not segment them against a compromise
of the edge proxy itself. That is the remaining Tier-2 path.

Two shapes that were considered and not taken: a Podman `.pod` with the admin
listeners on shared loopback (cleaner and more Podman-idiomatic, but it means
re-architecting the quadlets into a pod unit), and keeping a single flat network
and simply documenting the single security domain (cheapest, and strictly worse
than what is running).

### Cheap wins alongside it

- **`sslmode=require`** on the Kratos/Hydra → Postgres DSNs. On a shared bridge
  network a compromised container can sniff a peer; `sslmode=disable` puts session
  tokens and identity rows on the wire in clear.
- **Admin ports never published.** `:4434` / `:4445` (and the portal's `:4431`)
  carry **no** `PublishPort`. Confirmed correct in the shipped quadlets — keep it.

### Gating the admin surface — yes; the auth surface — no

A tempting question: put the whole entrypoint behind a long password or mTLS?
**You can't** — and the reason is definitional. An IdP exists to serve
*unauthenticated* callers: browsers hitting the login / passkey / email-code flows
before they have a session, and relying-party *servers* doing OAuth2 token
exchange, OIDC discovery, and JWKS fetches. Every OIDC app here is such a server.
A shared basic-auth password or client-cert wall on that surface breaks
passkey-first UX *and* breaks every OAuth2 RP. The public auth surface stays open;
you harden it (rate-limit, AAL2 step-up, phishing-resistant passkeys, the
response headers) rather than lock it.

The **admin surface** is the opposite case. Admins are a handful of people on
devices the operator controls, so the heavy lock belongs here.

**What runs: Caddy `basic_auth` scoped to `/admin/*`.** Caddy checks a bcrypt
hash per admin (`caddy hash-password`, hashes held in sops) and, unlike mTLS, is
not handshake-level, so it path-scopes cleanly inside the existing site with no
separate vhost and no CA. It is scoped to `/admin/*` only and must never cover
`/oauth2/*`, `/self-service/*`, or the login UI, or it breaks every RP and every
login. `rate_limit` is ordered before it so the password itself cannot be
hammered.

This is an outer network-reachability factor, **not** a replacement for in-app
authentication: the portal still requires an `aal2` session and the
`metadata_admin.admin` marker on the identity, checked server-side on every
`/admin` request (ADR 08). The AAL2 step-up redirect composes with basic auth
correctly: the browser leaves the basic-auth realm to authenticate at Kratos and
re-sends the cached credential on return. bcrypt cost per request is negligible
at admin scale, which is exactly why this belongs only on the admin path.

**Not built: mTLS client certs on a separate admin vhost.** The upgrade would be
a private CA issuing client certs to admin devices, with the admin UI served from
its own `admin.<host>` vhost under `client_auth require_and_verify` (mTLS is
handshake-level, so it needs the separate vhost). The estate runs a step-ca root
that could issue them, but this instance is single-PKI as deployed and mounts no
step-ca leaf (ADR 06). Nothing depends on this landing.

**Lock the origin against edge-bypass.** Only the front proxy should be able to
reach the origin, so an attacker cannot skip the edge and hit Caddy directly.
Binding Caddy to loopback behind the SNI router (as shipped) covers most of this.
This is compatible with the public flows because the *proxy* presents the
credential, not end users.

## 4. Secrets handling

- **Ory's own secrets are file-mounted; the portal's are not.** ENV secrets are
  readable via `/proc/<pid>/environ` and `podman inspect` to anything in the user
  namespace. Kratos and Hydra read their secrets from their config, which is
  rendered and mounted read-only, so the Hydra system secret and the
  cookie/cipher secrets are not in any process environment. The portal's are:
  its CSRF secret, admin bearers, SMTP URI and every OIDC client secret arrive
  as `Secret=…,type=env`. Closing that means a tmpfs-backed
  `Secret=…,type=mount` and a portal that reads from the path. It is a known
  gap, not an oversight.
- **The Hydra system secret is non-rotatable** — rotating it invalidates every
  issued token and client secret (a DB-rebuild event). Treat as break-glass;
  document the blast radius (see `docs/runbooks/secrets-rotation.md`).
- **Rotation must actually work.** If the deployment injects `_PREVIOUS` secret
  slots, the config must *read* them — otherwise rotation bounces every live
  session on restart. Either reference the previous slot in the config array, or
  follow the runbook's prepend-into-the-rendered-config model and drop the unused
  env slots.
- **Entropy:** cookie/HMAC secrets ≥ 32 bytes; the cipher secret is a fixed
  32-character key (don't widen it to 64 — that breaks Kratos boot). No plaintext
  secrets in any committed config — all values are `${ENV}` interpolation, sops at
  rest, dual-recipient so no single key loss locks you out.

## 5. Container baseline

Apply to every quadlet (Ory binaries, the portal, Postgres, Caddy):

- `NoNewPrivileges=true`
- `ReadOnly=true` + explicit `Tmpfs=` for the few writable paths (the Ory Go
  binaries and the Node app need no writable rootfs)
- `DropCapability=all` (these services need ~zero capabilities)
- Explicit `UserNS=keep-id:uid=…,gid=…` to fix file ownership intent
- Resource bounds (`PodmanArgs=--pids-limit … --memory …`) for DoS containment
- **Image pinning over auto-update.** Pin runtime images to `@sha256` digests and
  manage bumps through the pipeline + Renovate. `AutoUpdate=registry` on a mutable
  tag for a security-critical IdP is an auto-deploy path that bypasses your own
  e2e gate and signature verification — don't use it on the auth containers.

## 6. Supply-chain

- **Gate on CVEs, don't just record them.** Generating an SBOM (syft) is
  necessary but not sufficient — add an evaluation step that *fails the build*:
  `grype`/`trivy` on the image (`--fail-on high`), `npm audit --audit-level=high`
  on the portal, `govulncheck ./...` on the Go components.
- **Sign and verify by digest.** Keyless cosign signing by digest (already in the
  pipeline) plus a verify step before promotion closes the registry-tamper gap
  that digest-pinning alone leaves open.
- **Keep the toolchain current.** Renovate-annotate every pinned ARG (builder
  image, Go version, plugin versions); a missing annotation is a silent staleness
  blind spot. `npm ci` (never `npm install`) for reproducible installs; audit deps
  for `postinstall` scripts.

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
  hardening item here, and the basic-auth layer above is what currently stands
  in front of the gap.
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
