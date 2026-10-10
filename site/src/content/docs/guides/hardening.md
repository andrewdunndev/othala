# Hardening

Why each control sits where it does and, where one is absent, why. The "not
built" paragraphs are the ones worth reading; scope and reporting live in
`SECURITY.md`. Controls ship with the install rather than being delegated to a
WAF. Host root is out of scope and a compromised container is the tier most
controls target, but the threat that dominates at small scale is a lost,
stolen or shared device, and the worst case is a privacy breach, not fraud.

## Abuse resistance

Three unauthenticated risks: **email-bomb** against the code, recovery and
verification flows; **credential brute-force**, since Kratos ships no account
lockout by design; and **password-hash exhaustion**, where the argon2 memory
parameter that makes hashing strong becomes the denial-of-service lever.
`caddy/Caddyfile` carries reverse-proxy rate limiting for the Kratos browser
paths under a standing do-not-deploy marker — the directive is a third-party
module that must be compiled in, and a Caddy without it refuses to start rather
than degrading. `portal/src/lib/contact.ts` rate-limits the one unauthenticated
form the portal serves, and `kratos/kratos.yml` caps wrong-code submissions and
declines to confirm to a stranger whether an address is enrolled.

Not built, because the risk is real: **nothing caps concurrent argon2
operations**, so the memory-exhaustion lever is unbounded regardless of
source-IP diversity; and **the email-code lifespan outlives its login flow**, so
a code can arrive still valid against a flow that has expired.

## Browser hardening on the auth UI

`portal/src/middleware.ts` sets one header baseline on every response, asserted by
`e2e/playwright/tests/m-security-headers.spec.ts`. Two choices are non-obvious.

**There is no `script-src` and no `default-src` in the CSP.** A strict
`script-src` breaks the Kratos WebAuthn ceremony, which injects inline script
nodes, and breaks the portal's own inline theme setup. Adding one needs live
validation of every auth flow, so the CSP here is a framing, base-URI and
form-target control, **not XSS insurance**. Relatedly,
`form-action` cannot be `'self'` alone: it governs a submission's whole redirect
chain, and an OIDC login's redirect lands on the requesting app's own domain.

**`Referrer-Policy` is `same-origin`, not `no-referrer`.** Under `no-referrer`,
Chromium sends `Origin: null` on a same-origin form POST, which Astro's
`checkOrigin` rejects, making every admin mutation unreachable. `same-origin`
still sends nothing cross-origin, which matters because flow and
consent-challenge identifiers live in URLs. For the same reason no asset loads
from an external CDN.

## Admin-API isolation

**Ory's Kratos and Hydra admin APIs are unauthenticated by design.** The network
is the boundary, so how those ports are reachable is the most important
deployment decision.

**The trap: a second network alone does not segment it.** A socket bound to
`0.0.0.0` answers on every interface the container has. Attaching Kratos to an
additional internal-only network does not hide its admin port from the first
one. Segmentation needs that second network **and** an admin listener bound to
its address. A deployment doing only the first has the appearance of isolation
and none of it. The admin bind address is therefore a required variable, and
`scripts/render-config.sh` fails the render when any token is unset, though
nothing can check *which* address you supplied.

The portal reaches the admin API with no mTLS and no client certificate, so
**network isolation is the load-bearing control on that hop**. The residual: an edge proxy attached to both networks segments the admin APIs
against every container outside the auth stack, and not against a compromise of
the edge proxy itself. Both database DSNs likewise disable TLS (one private network, never crossing a host); an accepted risk.

**And no, you cannot put a password in front of the whole thing.** An identity
provider serves unauthenticated callers: browsers at login and relying-party
servers doing token exchange, discovery and JWKS fetches. A shared wall breaks
passkey-first login and every OAuth2 client. What is gated is `/admin`, where `requireAdminSession` in
`portal/src/lib/admin.ts` enforces an active session, `aal2` and the admin
marker on every request — `e2e/playwright/tests/d-admin-aal2-stepup.spec.ts` and
`f-aal2-bypass.spec.ts` hold that line.

The shape of that boundary, laid out end to end:

<figure class="diagram">
  <img src="/diagrams/trust-boundary.svg" alt="A browser reaches one hostname at the edge proxy, which terminates TLS. Inside one trust domain the admin APIs never leave: the app runs two listeners, a public SSR listener the edge reaches and an admin listener bound to PORTAL_ADMIN_BIND_HOST that the edge never touches; Kratos and Hydra each expose the edge a public API — self-service and sessions for Kratos, authorize, token and discovery for Hydra — while the app alone calls their admin APIs. Kratos and Hydra each keep a separate Postgres database. Admin APIs are reachable only from the app, never from the edge, enforced by scripts/render-config.sh, requireAdminSession, and pinned by d-admin-aal2-stepup.spec.ts and f-aal2-bypass.spec.ts.">
  <figcaption class="diagram-caption">Three ports on the network; the admin APIs are not among them</figcaption>
</figure>

## Secrets and the shipped baseline

**Ory's secrets are file-mounted; the portal's come from the process
environment**, and environment secrets are readable through `/proc` to anything
in the user namespace. Closing that means a tmpfs-backed mount and a reader that
takes a path — a known gap, not an oversight. No committed config holds
plaintext, and rotation shape (including why Hydra's system secret cannot rotate
at all) is a [Golden path](golden-path.md) commitment. This project ships no
deployment artifact: `e2e/compose.yml` is the canonical example and doubles as
the CI gate, so its container baseline is exercised on every tag rather than
described here. One property is worth knowing before copying it — the capability
drop is load-bearing, and without
`CAP_DAC_OVERRIDE` a 0600 config owned by one uid is unreadable by the image's
own user and every Ory service exits.

Not built: **no memory bound in the example compose** (bound memory in the
deploy plane, sized to the host; Kratos needs about 128 MB per concurrent
argon2 hash), so the hash-exhaustion lever above is otherwise unbounded;
**nothing evaluates the SBOM** that ships with each release, so a known CVE in
a shipped image fails nothing; and
**nothing verifies a signature before use** — a property of whatever runs the
image, not of this repository.

## Sessions and eviction

**The admin gate checks assurance AND freshness.** Session lifetime is
long for passkey-first daily use, so `/admin` additionally gates on *when* `aal2` was established: `isSessionFresh`
(`portal/src/lib/admin.ts`) redirects a stale session to the same step-up flow
as a missing `aal2`, before the admin-marker fetch. Window: 1h.

**Eviction must remove credentials, not just sessions.** Revoking sessions does
not delete enrolled credentials, so someone with a brief session can enrol
*their own* passkey and it survives both the revoke and a password reset. The
ladder, per `docs/runbooks/lost-device.md`: contain (admin revoke, cuts the
session now) → recover (self-service `/auth/recovery` if the victim is
locked out) → self-remove (the victim deletes the lost device's own
credential at `/auth/settings`) → last resort (delete the identity). For
webauthn/totp/lookup_secret the admin API can delete the whole credential
**type** in one call, but not for passkey: Kratos's admin API has no per-passkey
removal and refuses the type-delete too (upstream limitation). Self-remove is
therefore the only passkey eviction path, proven end to end by `e2e/playwright/tests/p-eviction.spec.ts` P3.

Revoking itself is one fan-out, and it shares an invariant with the login
path's own skip=true handling — Hydra's memory is never trusted on its own:

<figure class="diagram">
  <img src="/diagrams/session-revocation.svg" alt="Two panels. Left: when Hydra reports skip=true because it remembers a subject, the login handler re-verifies that a live Kratos session exists whose identity.id equals the remembered subject before honouring the skip; no live match forces interactive re-authentication, pinned by the FIX-A cases in portal/scripts/oauth2-handlers.test.mjs. Right: revokeSubject is the one in-process revocation fan-out, triggered by admin force-logout, sign-out-everywhere, or deactivate. Kratos sessions, Hydra's login-session and Hydra's consent-session are all revoked in a fixed order; this cuts sessions and remembered logins but not enrolled credentials, which is why the full eviction procedure above audits credentials and removes the affected one before it revokes.">
  <figcaption class="diagram-caption">Hydra remembers; Kratos authenticates — and revoking cuts both</figcaption>
</figure>

**No notification on email-code login.** A message to a secondary address would
collapse the detection window from "whenever the victim notices" to minutes.

Device-layer controls — screen lock, remote wipe — stay the operator's, and are
the real mitigation for a lost device. So do host hardening beneath the network
boundary, volumetric denial of service, and backup restore correctness across
Hydra's encryption at rest.
