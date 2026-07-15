# 03 — mTLS is proxy-originated, not in-app

## Status

Accepted (as a principle). **The dag instantiation was reverted 2026-07-01**:
the specific consumer this ADR was written to justify —
a step-ca-backed mTLS admin-proxy (`dag-kratos-admin-proxy`) fronting the Kratos
admin API on a dedicated `dag-admin` network — was removed because no
multi-site requirement justified it. The dag admin plane is now a **direct
internal hop**: `dag-portal` calls `http://10.89.11.10:4434` (Kratos admin)
over the `dag-internal` network, with the admin listener bound to that internal
IP and never host-published.

The proxy-holds-the-cert *pattern* still stands where a real TLS boundary
actually exists — see Decision. Cross-ref [06](06-two-pki.md) (two-PKI, the
step-ca CA whose client certs a proxy would present).

## Context

The hardening roadmap called for client authentication on the Kratos admin API,
which has no auth of its own (Ory's admin API is designed to be reached only
over a trusted network). The chosen mechanism was mTLS with a step-ca-issued
client cert, terminated by a `dag-kratos-admin-proxy` sidecar; two consumers
were to authenticate through it: the portal (Node/Astro) and a parked LDAP
bridge (Go).

Before landing that proxy, two *in-app* mTLS approaches were explored and
shelved:

**Portal: undici with a TLS Agent.** Node's `undici` supports a `connect`
option accepting `{ cert, key, ca }`, wired into the Ory SDK's `fetchApi`. It
was implemented in `feat/kratos-admin-mtls` (`buildMtlsFetchApi()` in
`admin-api.ts`) and rejected on supply-chain grounds: `undici` is not a direct
portal dependency, and pulling it in for one TLS use case added exposure the
operator would not accept when a proxy could hold the cert instead.

**LDAP bridge: Go stdlib crypto/tls.** `crypto/tls.Config{Certificates: [...]}`
is dependency-free and well understood, but non-uniform: the portal and the
bridge would handle mTLS differently, and each app would own cert loading,
renewal detection, and TLS error handling — recurring per-consumer surface.

**The proxy pattern** avoided all of that: the application talks plain HTTP to a
local sidecar; the sidecar (Caddy `reverse_proxy` + `transport http` with
`tls_client_auth`) presents the step-ca client cert to the upstream. The app
imports no TLS libraries and never sees a cert. This generalizes to any
consumer in any language that can speak plain HTTP to a loopback or pod-internal
address.

## Decision

**TLS is a proxy concern, not an application concern.** Application code speaks
plain HTTP; when a TLS boundary is required, a sidecar (Caddy) holds the cert
and terminates or originates TLS on the app's behalf. Applications do not import
TLS libraries, load certs, or handle cert renewal — renewal is the sidecar's
job on the existing `step ca renew` timer pattern.

What that means as-deployed:

- **The dag admin hop does NOT need this pattern, and no longer uses it.** For a
  single-host, single-operator instance there is no multi-site or cross-trust
  boundary between `dag-portal` and `dag-kratos`: both sit on `dag-internal`.
  Commit `fc4d8a5` removed `dag-kratos-admin-proxy.container`, `dag-admin.network`,
  the proxy Caddyfile + cert-lifecycle scripts, and the client/proxy cert-renew
  units. `dag-portal` now sets `KRATOS_ADMIN_URL=http://10.89.11.10:4434` and
  reaches the admin API directly. The control on the admin API is **network
  isolation, not client authentication**: `:4434` is bound to the dag-internal
  IP `10.89.11.10`, is never `PublishPort`ed, and the network is
  `Internal=true`. That lockdown is the load-bearing control, statically guarded
  by the instance's contract-gate assertions (N3: `dag-admin.network` absent =
  proxy-removal guard; `KRATOS_ADMIN_BIND_HOST=10.89.11.10` = bind guard;
  `KRATOS_ADMIN_URL=http://10.89.11.10:4434` on the portal = direct-hop guard).

- **The pattern is retained where a real cert boundary lives: the
  inference-serving path.** A `litellm-caddy` sidecar terminates TLS (a Let's
  Encrypt device cert, on its own FQDN) in front of the LiteLLM fabric and then
  speaks plain HTTP to it — the same "proxy holds the cert, app stays plain
  HTTP" shape, though there the boundary is *ingress* TLS-termination plus
  bearer virtual-key auth rather than egress mTLS (that path is deliberately
  *not* on the private step-ca mesh).

The shelved in-app branches (`buildMtlsFetchApi()`, `buildAdminTransport()`)
remain discarded. No `undici` direct dependency, and no `KRATOS_ADMIN_TLS_*`
env vars, exist in the portal.

## Consequences

- The dag admin plane's security now rests entirely on network isolation of
  `:4434` to `dag-internal`. This is appropriate for single-host,
  single-operator scope but is a weaker posture than mTLS: any container on
  `dag-internal` (postgres, hydra, migrations) can reach the unauthenticated
  admin API. The N3 gate guards the isolation; it does not add authentication.
  Re-introducing the proxy is the documented path if a multi-site or
  reduced-trust requirement returns.
- Removing the proxy deleted two moving parts per would-be consumer (a Caddy
  egress route + a cert-renew unit) and the entire `dag-admin` bridge. Less to
  break, less to renew, fewer failure modes at rebuild.
- The "TLS is a sidecar concern" principle keeps application code portable: the
  inference path proves a plain-HTTP app gains a real TLS edge by adding one
  sidecar and no app code. A future egress-mTLS consumer would re-adopt the same
  shape (Caddy `tls_client_auth` + step-ca client cert) without touching app
  code.
- Caddy sidecars mix ingress and egress concerns in one Caddyfile when they do
  both. Readable at the sidecar scope, but a thing to keep in mind.

## Alternatives considered

- **Keep the dag admin mTLS proxy.** Rejected as over-built for the deployed
  scope: it added a dedicated network, a proxy container, and two cert-lifecycle
  units to protect a same-host hop between two containers the operator already
  fully trusts. mTLS earns its keep across a trust boundary; there is none here.
- **undici (Node portal).** Rejected: a direct supply-chain dependency for one
  TLS use case, when a proxy can hold the cert instead.
- **Go stdlib crypto/tls (LDAP bridge).** Acceptable in isolation but
  non-uniform — each app owns cert loading and renewal, creating divergent
  maintenance surfaces. Moot while the LDAP bridge stays parked
  ([01](01-auth-substrate-ory.md)).
- **Shared egress Envoy on the estate edge.** Rejected: mixing WAN edge and
  intra-service egress in one config couples the edge to internal topology. The
  edge is for WAN; services handle their own TLS boundaries.
- **Dedicated Envoy egress sidecar per consumer.** Clean separation but adds an
  Envoy container per consumer for a one-hop task Caddy handles natively with
  less config surface.
