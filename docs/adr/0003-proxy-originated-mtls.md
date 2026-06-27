# 0003 — mTLS is proxy-originated, not in-app

## Status

Accepted. Supersedes two shelved in-app approaches: `buildMtlsFetchApi()`
(undici, Node portal) and `buildAdminTransport()` (Go stdlib crypto/tls,
kratos-ldap). See also [0006](0006-two-pki.md) (two-PKI, which establishes
the step-ca CA whose certs the proxy presents). Reference:
`campaigns/othala/proxy-mtls-egress-design.md`.

**Amendment (2026-06-26):** The mechanism decision (proxy-originated mTLS with
step-ca client certs via Caddy sidecar) stands. The kratos-ldap bridge consumer
cited in Context is shelved; the LDAP bridge is a parked separate project and is
not currently deployed. The portal is the live consumer of this pattern (reaching
`dag-kratos-admin-proxy` via its Caddy sidecar egress route).

**Amendment (2026-06-27 — N2 plain-internal exception):** The
portal→Kratos admin API hop is a **documented plain-internal exception** to
this ADR. Decision N2 chose Option B: the portal speaks plain HTTP on the shared
`dag-internal` network; no mTLS client cert is presented on the admin hop. The
Ory-native security model for the admin API is **isolation, not authentication**
— the API has no auth by design, and possession of network access (the
`dag-admin` bridge, which only the admin proxy and `dag-kratos` share) is the
authorization. This makes the `:4434` bridge-only lockdown (decision N3) the
load-bearing control; verify with a converge plus a negative test (admin port
unreachable off the bridge). All other outbound consumer egress (external
service-to-service, future mesh consumers) continues to follow the
proxy-originated mTLS model this ADR documents.

## Context

Gate 5 of the hardening roadmap requires client authentication on the
`dag-kratos-admin-proxy` endpoint (`:8445`), which fronts the Kratos admin
API. Two consumers need to authenticate: the portal (Node/Astro) and the
LDAP bridge (Go). The mechanism is mTLS with a step-ca-issued client cert.

Two in-app approaches were explored and shelved:

**Portal: undici with a TLS Agent.** The Node `undici` library supports a
`connect` option accepting `{ cert, key, ca }`, which can be wired into the
Ory SDK's `fetchApi` option. This was implemented in the
`feat/kratos-admin-mtls` branch (`buildMtlsFetchApi()` in `admin-api.ts`).
The operator rejected it on supply-chain grounds: undici is not a direct
dependency of the portal; pulling it in as a direct dependency for one TLS
use case added an indirect supply-chain exposure the operator was not willing
to accept when a cleaner alternative existed.

**LDAP bridge: Go stdlib crypto/tls.** Go's `crypto/tls.Config{Certificates:
[...]}}` is a well-understood path with no third-party dependency. This is
acceptable in isolation but non-uniform: it means the portal and the bridge
handle mTLS differently. Each in-app approach also means each application owns
cert loading, renewal detection, and TLS error handling -- recurring maintenance
surface per consumer.

**The proxy pattern.** Both consumers already have a local Caddy sidecar or can
add one. Caddy's `reverse_proxy` directive supports a `transport http` block
with `tls_client_auth <cert_file> <key_file>` and `tls_trust_pool file {...}`.
The consumer's application talks plain HTTP to a local address; the Caddy
sidecar presents the step-ca client cert when forwarding to the upstream proxy.
The application has no TLS code. The proxy holds the cert.

This pattern generalizes: any consumer in any language that can talk plain HTTP
to a loopback or pod-internal address gains mTLS toward internal endpoints by
adding a Caddy sidecar and pointing its upstream env var at the sidecar.

For the portal: `dag-caddy` already exists. An egress route is added on a
second listen address (e.g., `:8446`). The portal's `KRATOS_ADMIN_URL` points
at the sidecar address. Zero new containers.

For the LDAP bridge: one new quadlet (`dag-ldap-bridge-caddy.container`),
identical in shape to every other Caddy sidecar in the estate. The bridge's
`admin_url` points at the sidecar.

## Decision

mTLS toward internal endpoints is proxy-originated. Each consumer has a local
Caddy sidecar that holds the step-ca client cert and forwards plain HTTP from
the application to the mTLS-authenticated upstream. Application code talks plain
HTTP; it does not import TLS libraries, load certs, or handle cert renewal.

The `feat/kratos-admin-mtls` branch (undici, portal) and the shelved
`buildAdminTransport()` TLS branch (Go stdlib, kratos-ldap) are both discarded.
No undici direct dependency is added to the portal. No `KRATOS_ADMIN_TLS_*`
env vars are introduced.

## Consequences

- The proxy pattern is the reusable estate egress-mTLS primitive. Future
  consumers (in any language) gain mTLS toward internal endpoints by adding a
  Caddy sidecar and a one-line env var change. No per-language TLS code.
- Cert renewal is Caddy's job (via `step ca renew --force` on the existing
  renewal timer pattern). Application processes do not need to detect or
  respond to cert rotation.
- The ldap-bridge gains one new container (its Caddy sidecar). The portal gains
  none (reuses dag-caddy).
- Caddy sidecars mix ingress and egress concerns in one Caddyfile (one site
  block for inbound traffic, one for the egress hop). This is slightly
  mixed-direction but readable; the Caddyfile is the right scope for a sidecar
  that does both.
- The pattern extends to WAN/multi-host: an off-host consumer's local Caddy
  sidecar egresses over the LAN (or future Tailscale) to the same mTLS port.
  The consumer's app code does not change.

## Alternatives considered

- **undici (Node portal).** Rejected: adds a direct supply-chain dependency for
  one use case. The operator's supply-chain posture prefers proxy-level TLS
  termination over in-app TLS libraries when a proxy is already in place.
- **Go stdlib crypto/tls (kratos-ldap).** Acceptable in isolation but
  non-uniform. Each application would own cert loading and renewal detection
  independently, creating divergent maintenance surfaces.
- **Shared egress Envoy on the estate edge.** Rejected: mixing WAN edge and
  intra-dag egress in one Envoy config couples the edge to internal service
  topology. The edge is for WAN; services handle their own egress.
- **Dedicated Envoy egress sidecar per consumer.** Clean separation but adds
  one Envoy container per consumer (two new containers total) for a one-hop
  task that Caddy handles natively with less config surface.
