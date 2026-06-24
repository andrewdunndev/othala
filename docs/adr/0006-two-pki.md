# 0006 — Two-PKI: step-ca internal mesh CA + LE edge, never chained

## Status

Accepted (2026-06-22). step-ca is merged and live on carmine (the mesh CA, the
kratos-admin mTLS proxy, and user-scope cert renewal are all in production). The
internal mesh PKI is a first-class capability, and a hard requirement on it is
**secure certificate issuance over the WAN to consumers at multiple sites** (see
Context and Decision). Forward work: the WAN ACME + EAB roster surface and the SSH
CA. Reference: `campaigns/othala/step-ca-design.md`.

## Context

The estate has two classes of TLS:

1. **Browser-facing TLS** on public FQDNs (`dag.dunn.dev`, `cinema.dunn.dev`,
   etc.). Certificates must be trusted by public browser root stores. The
   standard approach is ACME with Let's Encrypt, via Caddy's DNS-01 challenge
   using the Cloudflare API. This is already in production.

2. **Internal service-to-service TLS** for cross-network hops between estate
   services. The most immediate case: when a kratos-ldap outpost living in
   `cinema.network` needs to reach the Kratos admin API (`dag-kratos-admin-proxy`,
   mTLS port `:8445`), it must present a client certificate. That certificate
   must be issued by a CA that the proxy trusts, and it must not be a
   browser-trusted CA, because the proxy is not browser-facing.

The forcing function is the LDAP outpost model: moving kratos-ldap into each
app's pod (rather than running one shared bridge in the dag stack) exposes the
Kratos admin API across a network boundary. Kratos admin is unauthenticated
god-mode in Ory OSS (create/delete any identity, read all credential metadata).
Crossing that boundary without mTLS is strictly worse than the shared bridge;
mTLS with per-outpost client certs is what makes the outpost model safer.

3. **Issuance over the WAN, to multiple sites.** The estate is not single-host.
   Compute and consumers will live across more than one machine and more than one
   physical site (a second GPU host, off-site nodes). A consumer that lives off the
   CA's host still needs an internal mesh cert, and it must be able to *obtain and
   renew* that cert over the WAN, without the CA being an open issuer on the public
   internet. So the internal CA is not a same-host convenience: it must support
   secure, authenticated certificate issuance to remote sites as a first-class
   requirement, while never widening its trust to anything that merely reached it
   over the network.

The question was whether to run one PKI (extend LE to internal certs) or two.

**One PKI (chain LE to internal).** Let's Encrypt could theoretically sign an
intermediate CA that issues internal certs. This is technically possible but
operationally wrong: a compromise of the internal CA (stored on the homelab)
would also compromise the publicly-trusted certificate chain, because the
internal CA's cert was signed by a publicly-trusted root. The blast radius
crosses from "internal service compromise" to "public TLS compromise." The
reverse (getting LE to cross-sign an internal root) is not possible; LE does
not sign intermediate CAs for non-public use.

**Two PKIs (separate roots, never chained).** step-ca runs as its own rootless
service with a self-signed root. It issues certs only for internal service
identities and outpost clients. The root is in sops; the CA runs with a
password-protected key. Public browsers never see a step-ca cert. Internal
services never present an LE cert. Each PKI has its own blast radius and
upgrade cycle.

step-ca is the natural choice for the internal CA:

- Runs as a single static binary (same pattern as Kratos, Hydra).
- Native ACME support (for automated renewal), plus JWK and X5C provisioners
  for one-shot issuance.
- `step` CLI for cert inspection and manual issuance.
- Integrates cleanly with the existing Caddy `transport http { tls_client_auth
  ... }` pattern (ADR-0003).

Root key custody decision: the step-ca root key is stored in sops (encrypted at
rest, backed up with the sops secrets store). No airgap. The operator accepted
this tradeoff: an airgapped root is the correct posture for a production
enterprise CA, but the additional operational friction (offline ceremony for
every new intermediate) is not justified at family scale where the operator is
the sole maintainer.

## Decision

Two independent trust roots. Let's Encrypt (via Caddy DNS-01 ACME) issues certs
for browser-facing FQDNs. step-ca (self-hosted, rootless, sops-backed root key)
issues certs for internal service identities and outpost clients. The two PKIs
are never chained: no cross-signing, no shared intermediate. A browser never
sees a step-ca cert; an outpost never presents an LE cert.

step-ca runs as service user `step-ca` (uid 2000, the lowest service slot,
signifying tier-0 trust infrastructure). Its service certificate is renewed by
the existing `dag-proxy-cert-renew` timer pattern extended to cover outpost
client certs.

**WAN, multi-site issuance is via ACME with External Account Binding (EAB),
"roster mode."** step-ca exposes ACME through the edge so a consumer at another
site can enroll and renew over the WAN, but the ACME endpoint requires an EAB
key so it is not an open issuer: only outposts the operator has pre-registered
(on the roster) can obtain a cert, and each gets an account bound to its
identity. Off-site consumers use the same local-Caddy-sidecar pattern as on-host
ones (ADR-0003): the sidecar holds the ACME/EAB credential, obtains a short-lived
cert from step-ca, and presents it mTLS to the target endpoint. Leaves are
short-lived with automatic ACME renewal, so a remote site self-heals its certs
without operator involvement. Reaching the CA over the WAN grants nothing by
itself; the EAB roster plus the per-leaf identity are the trust boundary.

## Consequences

- step-ca is a dependency for any service that needs internal mTLS. It must be
  running and reachable before the LDAP outpost, the kratos-admin-proxy, and any
  future internal mTLS endpoint can operate. Its availability is a pre-condition
  for the LDAP bridge across a network boundary.
- Root key custody is sops-backed (not airgapped). If the sops age key and the
  step-ca root key are both compromised simultaneously, all internal certs are
  untrustworthy. Accepted at family scale; document clearly.
- Cert renewal is automatic via the existing `step ca renew --force` timer
  pattern. Manual re-issuance is needed only when adding a new outpost.
- The two-PKI boundary simplifies reasoning: "does this endpoint need a
  browser-trusted cert?" determines which PKI issues it. Mixed PKI (where the
  same endpoint might have either) would add an extra question to every new
  service deployment.
- WAN issuance is secured by the EAB roster, not by network reachability. The
  ACME surface can face the WAN (through the edge) because an attacker who reaches
  it cannot obtain a cert without a rostered EAB key. This decouples internal mTLS
  from any network-overlay decision: a remote site needs cert credentials, not
  membership in a private network. Adding an overlay later (e.g. Tailscale) is
  additive defense-in-depth, never the thing that gates issuance.
- Short-lived leaves + automatic ACME renewal mean remote sites self-heal. The
  cost is that the WAN ACME endpoint and the EAB roster become availability and
  custody surfaces of their own: if the roster key leaks, it must be rotated and
  the affected accounts re-bound; if the ACME edge is down, remote renewals stall
  (mitigated by leaf lifetimes long enough to ride out an outage).
- Adopters who want a different internal CA (HashiCorp Vault PKI secrets engine,
  cfssl, etc.) can substitute it. The Caddy `tls_client_auth` and
  `tls_trust_pool` directives are CA-agnostic; the cert files and the trust
  anchor are the interface.

## Alternatives considered

- **No internal CA; use pre-shared keys or bearer tokens instead of mTLS.**
  Simpler for the near-term LDAP-only case. Does not generalize: bearer tokens
  per endpoint require per-endpoint secret rotation and do not carry identity
  (you know a caller has the token, not which service is calling). mTLS with
  per-outpost client certs gives both confidentiality and authenticated identity.
- **Tailscale as the internal network layer (no explicit mTLS).** Tailscale
  provides WireGuard-based mesh networking with device authentication. It is
  additive, not a substitute: it secures the network layer but does not provide
  application-layer client certs. The outpost model requires the proxy to
  authenticate the specific caller (outpost-portal vs. outpost-ldap-bridge), not
  just "a device on the Tailscale network." step-ca is the right layer for that
  identity. (Tailscale is also not deployed today; Tailscale is an additive
  future layer, not load-bearing auth infrastructure.)
- **Chain internal certs under LE.** LE does not sign intermediate CAs for
  non-public use. Reverse-chaining (signing an internal root under a public CA)
  is not possible via ACME. Rejected.
- **One internal CA for both public and internal certs (private CA, no LE).**
  Requires pre-installing the root in all family browsers. Ongoing browser
  maintenance, broken auto-update paths, trust-store divergence across Apple
  devices. The estate's browser-facing endpoints are served by public CDN-backed
  FQDNs; LE is the correct CA for that surface.
