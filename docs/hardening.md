# Hardening & secure-deployment guide

> **Status: first draft (2026-06-07).** Companion to `SECURITY.md` (scope &
> reporting) and `docs/security-review-2026-06-07.md` (the dated adversarial
> review this guide acts on). This is the *open best-practices* document: how to
> run Othala so that the install itself is secure, without leaning on any
> particular edge provider.

## Posture: security lives in the install

Othala is an authentication substrate — it issues the tokens and gates the
access everything downstream trusts. The controls that keep it safe must ship
**with the install**, not be delegated to a CDN or WAF in front of it. A
Cloudflare/edge WAF is welcome as an *outer* layer of defence-in-depth, but
**Othala must be safe to self-host without one.** Where this guide names an
intrinsic control (rate-limit, response headers, admin isolation), that control
is the load-bearing one; the edge is optional redundancy.

This reverses one earlier scoping decision: application-layer abuse resistance
(flood/brute-force/hash-exhaustion) was previously treated as "the operator's
edge concern." It is now in scope and shipped-mitigated. See `SECURITY.md`.

## Threat model (summary)

Tiers (full detail in `docs/security-review-2026-05-04.md`):

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

Intrinsic controls Othala ships:

- **Reverse-proxy `rate_limit` on `/self-service/*`.** The bundled Caddy config
  rate-limits the self-service flows per client IP. In the standard install
  (Caddy at the edge), `{remote_host}` *is* the client IP and this works as
  shipped. **Deployment caveat:** if you front Caddy with an L4 / SNI-passthrough
  proxy (so Caddy sees a fixed upstream IP), the per-client key collapses to one
  global bucket. Fix it *at your proxy hop*, CDN-independently: have that proxy
  speak **PROXY protocol** to Caddy and add `trusted_proxies` so Caddy recovers
  the real client IP. Do **not** depend on a CDN-injected header (e.g.
  `CF-Connecting-IP`) as the only source — that ties the control to one provider.
- **Concurrency bound on password hashing.** A `max_conns` cap on the Kratos
  upstream in Caddy bounds how many argon2 operations can run at once, capping the
  memory-exhaustion lever regardless of source-IP diversity. This is CDN-independent
  and belongs in the shipped config.
- **Ory flow config:** keep `code.config.max_submissions` explicit and align the
  code lifespan with the login-flow lifespan so a delivered code can't outlive its
  flow. `notify_unknown_recipients: true` on recovery is the friendlier choice for
  a small known population.

Optional edge layer: a WAF rate-limit rule on `/self-service/*` adds redundancy
and sheds volume before it reaches the origin. It is **not** a substitute for the
intrinsic controls above.

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
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Permissions-Policy` (deny camera/mic/geo), `Cross-Origin-Opener-Policy: same-origin`.
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

In the default single-network deployment, every container shares one Podman
network, and the admin APIs are reachable from any container on it. This is a
deliberate **single security domain**: a compromise of *any* one container
(Tier 2) can reach the admin APIs and, in a few calls, create an admin identity
or reset any credential. This is acceptable for a single-tenant homelab *if you
accept that the pod/network boundary is the wall* — but it is the thing to harden
if you want to shrink the blast radius.

### Why a second network alone does not segment

A listening socket bound to `0.0.0.0` answers on **every** network interface the
container has. Attaching Kratos to a second `dag-admin.network` does **not** hide
`:4434` from the first network — it still answers there. To segment, you must
**also bind the admin listener to a specific address** so it stops answering on
the public interface. Two shapes:

**Option A — static-IP admin network (no pod restructure).**
1. Create `dag-admin.network` with a fixed subnet.
2. Attach Kratos, Hydra, and the portal (the only admin consumer) to it with
   static `IP=` addresses.
3. Set Ory `serve.admin.host` to each container's **admin-network IP** (not
   `0.0.0.0`).
4. Keep Caddy and every non-admin service **off** `dag-admin.network`.
5. Point the portal's `KRATOS_ADMIN_URL` / `HYDRA_ADMIN_URL` at the admin-net
   addresses.

A compromised Caddy — the most exposed container — then has no route to the admin
APIs. Cost: fiddly (static IPs, admin-host binding, DNS targeting), but no rebuild.

**Option B — a Podman pod + loopback-bound admin (cleanest).**
Group Kratos, Hydra, portal, and postgres in a pod (shared network namespace =
shared `localhost`). Bind the Ory admin listeners to `127.0.0.1`; the portal
reaches them on loopback — the same pattern the portal already uses for its own
admin endpoints (`127.0.0.1:8431`). Caddy stays **outside** the pod and reaches
only the pod's published public ports. The admin APIs become unreachable from
anything but the in-pod admin consumers. Cost: re-architecting flat-network
quadlets into a `.pod` unit, but the most Podman-idiomatic isolation.

**Option C — keep the single domain, document it.** A legitimate homelab posture:
accept the single security domain (the foothold precondition — a container RCE —
is itself non-trivial on a single-tenant box), and invest the effort in the cheap
wins below instead. This is what the 2026-05-04 review chose.

### Cheap wins regardless of A/B/C

- **`sslmode=require`** on the Kratos/Hydra → Postgres DSNs. On a shared bridge
  network a compromised container can sniff a peer; `sslmode=disable` puts session
  tokens and identity rows on the wire in clear.
- **TLS on the LDAP bridge.** glauth must not serve LDAP BIND in cleartext — the
  service bind password (and any user BIND) crosses the network unprotected.
  Provision a cert (self-signed CA is fine for internal-only consumers) before the
  bridge serves real auth.
- **Admin ports never published.** `:4434` / `:4445` (and the portal's `:8431`)
  carry **no** `PublishPort`. Confirmed correct in the shipped quadlets — keep it.

### Gating the admin surface — yes; the auth surface — no

A tempting question: put the whole entrypoint behind a long password or mTLS?
**You can't** — and the reason is definitional. An IdP exists to serve
*unauthenticated* callers: browsers hitting the login / passkey / email-code flows
before they have a session, and relying-party *servers* doing OAuth2 token
exchange, OIDC discovery, and JWKS fetches (Tailscale, Grafana, Audiobookshelf).
A shared basic-auth password or client-cert wall on that surface breaks
passkey-first UX *and* breaks every OAuth2 RP. The public auth surface stays open;
you harden it (rate-limit, argon2 bound, AAL2 step-up, phishing-resistant
passkeys, the response headers) rather than lock it.

The **admin surface** is the opposite case — admins are a handful of people whose
devices you control, so the heavy lock belongs here. This composes *on top of*
the app's own AAL2 + email-allowlist gate: it is an outer network-reachability
factor, not a replacement for in-app authentication. A phased path that does not
gate the deployment on any external infrastructure:

**Phase 1 — Caddy `basic_auth` on the admin path (self-contained, day-one).**
Caddy's `basic_auth` checks a bcrypt hash (`caddy hash-password`) and, unlike
mTLS, is *not* handshake-level, so it path-scopes cleanly inside the existing
site — no separate vhost, no CA:

```
@admin path /admin/*
basic_auth @admin {
    andrew.dunn <bcrypt-hash>
    ashley.dunn <bcrypt-hash>
}
reverse_proxy @admin dag-portal:8080
```

Scope it to `/admin/*` only — it must never cover `/oauth2/*`, `/self-service/*`,
or the login UI. Use a long random password per admin (individually revocable),
sops the hashes, and add `/admin/*` to the rate-limit zone so the password itself
can't be hammered. The AAL2 step-up redirect still works: it leaves the basic-auth
realm to authenticate and the browser re-sends the cached credential on return.
bcrypt-per-request cost is negligible at admin scale (two people) — which is
exactly why this belongs only on the admin path, never a public one.

**Phase 2 — mTLS client certs (upgrade, not a prerequisite).** Stand up a private
CA (e.g. Smallstep `step-ca`), issue client certs to operator/spouse devices, and
serve the admin UI from a **separate `admin.<host>` vhost** with `client_auth
require_and_verify` against the CA root (mTLS is handshake-level, so it needs the
separate vhost). Keep `basic_auth` as a second factor or drop it. The deployment
ships on Phase 1; the CA lands whenever.

**Alternative — Tailscale-only `/admin/*`.** Bind the admin path to a tailnet-only
listener so it is not on the public internet at all. No chicken-and-egg:
Tailscale's *own* login rides the public `/oauth2/*` path, not `/admin`, so gating
`/admin` behind the tailnet does not lock you out of Tailscale. Stronger than
basic_auth (no public exposure) if you are always on your tailnet to administer.

- **Lock the origin against edge-bypass.** Ensure only your front proxy can reach
  the origin, so an attacker can't skip the edge and hit Caddy directly. Binding
  Caddy to loopback behind the SNI router (as shipped) covers most of this; if a
  CDN fronts the deployment, add authenticated-origin-pull or an edge-IP allowlist.
  This is compatible with the public flows because the *proxy* presents the
  credential, not end users.

## 4. Secrets handling

- **Prefer file-mounted secrets over `type=env` for the high-value ones.** ENV
  secrets are readable via `/proc/<pid>/environ` and `podman inspect` to anything
  in the user namespace. The non-rotatable Hydra system secret, the cookie/cipher
  secrets, the SMTP credentials, and the admin bearers are better delivered as a
  rendered config file (Ory reads secrets from its config) mounted read-only, or
  via a tmpfs-backed `Secret=…,type=mount`.
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

Apply to every quadlet (Ory binaries, the portal, the bridge, postgres, Caddy):

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

- **Session length, tiered.** A 90-day session is long for an admin. Keep
  passkey-first + email-code for non-admins (don't make daily use miserable), but
  shorten non-admin sessions (e.g. 30 days) and enforce **admin AAL2 *freshness***
  — re-prompt for the second factor after a few hours, not just "AAL2 present at
  some point." Checking that the factor is present but never re-checking freshness
  means a stolen admin browser is good for the full session lifetime.
- **Eviction must remove credentials, not just sessions.** `revokeSubject` /
  "force re-login" terminates active sessions — it does **not** delete enrolled
  credentials. A thief who gets a brief session can enrol *their own* passkey;
  that credential survives the revoke and a password reset, and they log straight
  back in. **The correct lost-device procedure is: audit the identity's
  credentials → delete any the user doesn't recognise → *then* revoke.** The admin
  UI surfaces enrolled credentials and supports per-credential deletion for exactly
  this. See `docs/runbooks/admin-recovery.md`.
- **Notify on email-code login.** A "new sign-in via email code" notification to a
  secondary address collapses the detection window from "whenever the victim
  notices" to minutes.

## What stays the operator's responsibility

- Device-layer controls (screen lock, per-app lock, remote wipe) — outside
  Othala's enforcement perimeter but the real mitigation for lost devices.
- Host hardening (bootc/immutable base, ZFS, rootless Podman) — the secondary
  boundary under the pod/network boundary.
- Volumetric L3–L4 DDoS — needs upstream capacity to absorb; an edge concern.
- Backups & their restore correctness across Hydra's encryption-at-rest.
