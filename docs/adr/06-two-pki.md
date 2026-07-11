# 06 — Two-PKI: step-ca internal mesh CA + LE edge, never chained

## Status

Accepted as an estate-wide principle: a self-signed internal root (step-ca,
`federatedRoots: null`) for service-to-service mTLS, Let's Encrypt for
browser- and device-facing edge FQDNs, and the two roots **never cross-signed**.

Superseded-in-practice for dag: **dag is single-PKI as deployed.** The mTLS
consumer this ADR was written around — the `dag-kratos-admin-proxy` hop that
crossed a network boundary to the Kratos admin API — was **removed 2026-07-01**
(see [03](03-proxy-originated-mtls.md)). dag today terminates only Let's Encrypt
at its Caddy edge and has no internal step-ca leaf; the portal reaches the Kratos
admin API directly over an `Internal=true`, `isolate=true` bridge (`dag-internal`)
instead of over mTLS. The two-root principle stands, but dag is no longer a
consumer of the internal root — the live consumer is the inference serving path
(see Decision).

## Context

The estate has two classes of TLS:

1. **Browser/device-facing TLS** on public FQDNs (`dag.dunn.dev`, `llm.dunn.dev`,
   `chat.dunn.dev`, …). Certificates must be trusted by public root stores out of
   the box — an iOS device or a family browser cannot be asked to install a
   private root. The standard approach is ACME with Let's Encrypt, via Caddy's
   DNS-01 challenge using the Cloudflare API. This is in production at every edge.

2. **Internal service-to-service TLS** for cross-network hops between estate
   services that are not browser-facing. Such an endpoint must present/verify a
   client or server certificate issued by a CA the peer trusts, and it must *not*
   be a browser-trusted CA — the endpoint is never on the public web, and a
   browser-trusted internal CA needlessly widens blast radius.

The question was whether to run one PKI (extend LE to internal certs) or two.

**One PKI (chain LE to internal).** Let's Encrypt could theoretically sign an
intermediate that issues internal certs. Operationally wrong: a compromise of the
internal CA (stored on the homelab) would also compromise the publicly-trusted
chain, because the internal CA's cert was signed by a publicly-trusted root. The
blast radius crosses from "internal service compromise" to "public TLS
compromise." The reverse — getting LE to cross-sign an internal root — is not
possible; LE does not sign intermediate CAs for non-public use.

**Two PKIs (separate roots, never chained).** step-ca runs as its own rootless
service with a self-signed root (`federatedRoots: null` — no federation, no
cross-signing). It issues certs only for internal service identities. Public
browsers never see a step-ca cert; internal endpoints never present an LE cert.
Each PKI has its own blast radius and upgrade cycle.

step-ca is the natural internal CA: a single static binary (same pattern as
Kratos/Hydra), native ACME plus JWK/X5C provisioners for one-shot issuance, a
`step` CLI for inspection, and clean integration with Caddy's `tls_client_auth` /
mesh-cert patterns. The crown-jewel posture: the running instance holds only the
intermediate key; the root key lives sops-encrypted and, in the production flow,
never touches the CA host (the live prototype collapses that onto the host with
the shred step operator-manual).

## Decision

Two independent trust roots, never chained. Let's Encrypt (via Caddy DNS-01 ACME)
issues certs for browser/device-facing FQDNs. step-ca (self-hosted, rootless,
self-signed root, `federatedRoots: null`) issues certs for internal service
identities. No cross-signing, no shared intermediate: a browser never sees a
step-ca cert; an internal mesh endpoint never presents an LE cert.

**As deployed, the live consumer of the internal root is the inference serving
path, not dag.** step-ca (the systemd unit is `step-ca` — pre-rename; the deploy
module and service user are `stepca`) fronts its issuance API at the internal
mesh FQDN `tyr.dunn.dev` (envoy SNI passthrough → `stepca:9000`), authenticated
by a JWK provisioner. The `infer` service's `litellm-caddy` sidecar serves the
`norn.dunn.dev` metering listener with a step-ca-issued mesh leaf (issued and
renewed via `tyr.dunn.dev` using the JWK provisioner), and TLS terminates there
behind envoy's L4 SNI passthrough. This is the metering data-plane hop; othala is
deliberately absent from it (bouncer, never meter). The inference edge itself
(`llm.dunn.dev`) is the **sanctioned LE exception**: it faces iOS/agent clients,
so it holds an LE device cert rather than a mesh cert — the two-PKI split is
exactly what lets that edge be LE while the internal metering hop is step-ca. See
iac `docs/adr/network/0003-inference-serving-topology.md` for the inference
topology.

dag is out of the internal-PKI picture entirely: its Caddy edge terminates LE
(`tls { dns cloudflare }`), and no dag quadlet mounts a step-ca leaf. dag is
single-PKI as deployed.

## Consequences

- step-ca is a hard dependency only for services that need an internal mesh cert.
  Today that is the inference metering hop (`infer` / `litellm-caddy` on
  `norn.dunn.dev`); step-ca is a tier-0 unit that must be healthy before those
  consumers converge. dag no longer depends on it.
- dag's admin-plane security is now network isolation, not mTLS: the Kratos admin
  API binds an `Internal=true` + `isolate=true` bridge reachable only by
  co-networked dag containers. Simpler surface, but the mTLS-authenticated-caller
  property (which specific service is calling admin) is gone — the boundary is now
  "is on `dag-internal`," not "presents a rostered client cert" (see
  [03](03-proxy-originated-mtls.md)).
- Root-key custody is sops-backed. If the sops age key and the step-ca root/
  intermediate material are compromised together, all internal certs are
  untrustworthy. Accepted at family scale; documented, not airgapped.
- The two-PKI boundary keeps reasoning cheap: "does this endpoint face a browser
  or device?" decides which CA issues it — LE if yes (`dag.dunn.dev`,
  `llm.dunn.dev`), step-ca if it is an internal mesh hop (`norn.dunn.dev`). A
  single mixed PKI would add that question to every new endpoint.
- The internal CA can face the WAN through the edge (envoy SNI → `tyr.dunn.dev`)
  without becoming an open issuer, because issuance requires the JWK/EAB
  provisioner credential, not mere network reachability. Adding a network overlay
  (e.g. Tailscale) later is additive defense-in-depth, never the thing that gates
  issuance.
- Adopters who want a different internal CA (Vault PKI, cfssl, …) can substitute
  it: the mesh-cert files and the trust anchor are the interface, not step-ca
  specifically.

## Alternatives considered

- **Single PKI everywhere (chain internal under LE).** LE does not sign
  intermediate CAs for non-public use; reverse-chaining an internal root under a
  public CA is not possible via ACME. Rejected on both feasibility and blast
  radius.
- **One private CA for both edge and internal (no LE).** Requires pre-installing
  the root in every family browser and device — ongoing trust-store maintenance,
  broken auto-update paths, and no clean story for an iOS client that trusts LE
  out of the box. The edge is served by public-CDN-backed FQDNs where LE is the
  correct CA.
- **No internal CA; bearer tokens or pre-shared keys instead of mesh certs.**
  Simpler for a single hop. Does not carry service identity (you learn a caller
  holds the token, not which service it is) and needs per-endpoint secret
  rotation. Where an internal hop remains (inference metering), a step-ca leaf
  gives confidentiality plus authenticated identity for free.
- **Tailscale as the internal layer, no explicit mTLS.** WireGuard mesh with
  device auth secures the network layer but not application-layer service
  identity, and it is not deployed today. Additive if adopted later; not a
  substitute for the CA, and not load-bearing auth infrastructure now.
