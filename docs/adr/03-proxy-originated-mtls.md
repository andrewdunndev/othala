# 03 — mTLS is proxy-originated, not in-app

## Status

Accepted (2026-08-15). Application code speaks plain HTTP and never loads a
certificate; where a real TLS boundary exists, a Caddy sidecar holds the cert.
**The dag Kratos-admin hop needs no TLS boundary and has none** — `dag-portal`
calls the Kratos admin API directly over the `Internal=true`, `isolate=true`
`dag-internal` bridge. The `dag-kratos-admin-proxy` sidecar and the dedicated
`dag-admin` network this record was written to justify were removed 2026-07-01
(`iac` commit `fc4d8a5`); **network isolation, not client authentication, is the
load-bearing control on that hop.** This record carries no IP literal — the
authority is the deploy-plane contract gate named in Decision.

The proxy-holds-the-cert pattern still stands where a real cert boundary lives.
That is the inference-serving path, and its PKI facts belong to
[06](06-two-pki.md) — this record does not restate them.

See also [01](01-auth-substrate-ory.md) (the LDAP bridge, one of the two
consumers this proxy was designed to serve, retired without ever running) and
[08](08-admin-authority-model.md) (the admin-API write boundary this hop
carries).

## Context

The hardening roadmap called for client authentication on the Kratos admin API,
which has no auth of its own (Ory's admin API is designed to be reached only
over a trusted network). The chosen mechanism was mTLS with a step-ca-issued
client cert, terminated by a `dag-kratos-admin-proxy` sidecar; two consumers
were to authenticate through it: the portal (Node/Astro) and the glauth→Kratos
LDAP bridge (Go), which was then still a planned component.

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
imports no TLS libraries and never sees a cert. One shape covers any consumer
that can speak plain HTTP to a sidecar, whatever it is written in — which is
what made it preferable to two per-language implementations of the same hop.

## Decision

**TLS is a proxy concern, not an application concern.** Application code speaks
plain HTTP; when a TLS boundary is required, a sidecar (Caddy) holds the cert
and terminates or originates TLS on the app's behalf. Applications do not import
TLS libraries, load certs, or handle cert renewal. Renewal belongs to the sidecar
or to the host lifecycle beside it: Caddy renews its own ACME certs, and a
step-ca mesh leaf is renewed by a host timer that rewrites the sidecar's mounted
cert files, which Caddy re-reads on the next handshake ([06](06-two-pki.md)).

What that means as deployed:

- **The dag admin hop does not need this pattern and no longer uses it.** For a
  single-host, single-operator instance there is no multi-site or cross-trust
  boundary between `dag-portal` and `dag-kratos`: both sit on `dag-internal`.
  Commit `fc4d8a5` removed `dag-kratos-admin-proxy.container`,
  `dag-admin.network`, the proxy Caddyfile and cert-lifecycle scripts, and the
  client/proxy cert-renew units. `dag-portal` now carries a `KRATOS_ADMIN_URL`
  pointing at the Kratos admin listener on `dag-internal` and reaches the admin
  API directly. The control on that API is **network isolation, not client
  authentication**: the admin listener binds the dag-internal address, `:4434`
  is never `PublishPort`ed, and the network is `Internal=true`.

  **This record deliberately carries no address literal.** The authority for the
  bind address, for `:4434` never being host-published, and for
  `dag-admin.network` staying absent is the deploy-plane contract gate
  `iac deploy/checks/check_dag_contract.py`, check `N3` — it fails the deploy if
  any of the three regresses, and it is where an operator or an agent should
  read the current value. A previous revision of this record pinned the address
  in five places; the deploy plane renumbered its networks and every one of them
  became wrong, leaving the ADR contradicting the gate that enforces it. A gate
  cannot rot silently: it fails.

- **The pattern is retained where a real cert boundary lives: the
  inference-serving path.** The `litellm-caddy` sidecar terminates TLS in front
  of the LiteLLM fabric and then speaks plain HTTP to it — the same "proxy holds
  the cert, app stays plain HTTP" shape. There the boundary is *ingress*
  TLS-termination plus bearer virtual-key auth rather than egress mTLS. Which
  listener holds which CA's cert is [06](06-two-pki.md)'s to state, not this
  record's; an earlier revision answered it here and answered it wrongly.

The shelved in-app branches (`buildMtlsFetchApi()`, `buildAdminTransport()`)
remain discarded. The portal has no `undici` direct dependency and no
`KRATOS_ADMIN_TLS_*` env vars.

## Consequences

- The dag admin plane's security rests entirely on network isolation of `:4434`
  to `dag-internal`. This is appropriate for single-host, single-operator scope
  but is a weaker posture than mTLS: any container on `dag-internal` (postgres,
  hydra, migrations) can reach the unauthenticated admin API. The `N3` gate
  guards the isolation; it does not add authentication. Re-introducing the proxy
  is the documented path if a multi-site or reduced-trust requirement returns.
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
  maintenance surfaces. Moot in any case: the LDAP bridge was retired 2026-06-29
  having never run ([01](01-auth-substrate-ory.md)), and its code sits in an
  unmaintained reference repo.
- **Shared egress Envoy on the estate edge.** Rejected: mixing WAN edge and
  intra-service egress in one config couples the edge to internal topology. The
  edge is for WAN; services handle their own TLS boundaries.
- **Dedicated Envoy egress sidecar per consumer.** Clean separation but adds an
  Envoy container per consumer for a one-hop task Caddy handles natively with
  less config surface.
