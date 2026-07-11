# 02 — Custom portal with in-app OIDC registrar

## Status

Accepted. The standalone consent service (v0.1.x) was retired and its behavior
folded into the portal at v0.1.4. The in-app OIDC registrar converged at v0.2.0.
See also [01](01-auth-substrate-ory.md) (the substrate choice that requires
a BYO portal).

## Context

Hydra is a pure OAuth2/OIDC authorization server. It has no built-in UI. Every
consent, login, and logout challenge must be handled by a separate application
that Hydra redirects to. The question was how to structure that application and
where to put the OIDC client registration logic.

**v0.1.x: separate consent service.** The original shape had a dedicated Go
`consent/` service handling Hydra's challenge callbacks, plus a separate Go
`util/` runner that called `hydra admin create-oauth2-client` via shell. The
Astro portal handled the family-facing UI (tile dashboard, auth pages). Three
processes: portal, consent, util runner.

This created a service boundary with no value at family scale. The consent
handler is request/response stateless -- it reads a challenge from Hydra and
accepts or rejects it. There was no reason it needed to be a separate process
once the portal was already a Node SSR application with direct network access
to Hydra's admin port.

**Workers adapter: tried and reversed.** The original portal design targeted
Cloudflare Workers (Astro Workers adapter). This was reversed when it became
clear that the Kratos and Hydra admin ports (`kratos:4434`, `hydra:4445`) are
unreachable from a Worker -- they are bound to the pod-internal network. A
Worker cannot reach a pod-internal address from Cloudflare's edge. The admin
port access requirement jointly with "Astro on Workers" was inconsistent. Moving
the app into the same pod as Kratos and Hydra resolved the access problem and
eliminated the wrangler deploy step.

**OIDC client registration.** The original approach used the `hydra` CLI
(`apply-clients.sh`, a shell script per client in `hydra/clients/<slug>.yaml`).
At v0.2.0 this became a typed TypeScript runtime (`portal/src/lib/register-clients.ts`)
that reads the unified `<slug>.yaml` manifests from `MANIFEST_DIR`, validates
them, and calls the Ory SDK's `OAuth2Api` to create or update clients. The
registrar runs automatically on portal startup and on `SIGHUP` (the operator
reloads clients with a one-shot reconcile command driving pyinfra's post-deploy
hook, which deploys the catalog manifests to the host and sends `SIGHUP` to the
portal process). It is not route-triggered.

**At v0.1.4:** the Go `consent/` service source was deleted. Its behavior --
the Hydra login, consent, and logout challenge handlers -- moved into the portal
as `portal/src/lib/oauth2-handlers.ts`. The Go `util/` apply runner was deleted
at the same time; OIDC client registration moved to the TypeScript registrar.

## Decision

One all-TypeScript Astro Node SSR application (the Othala app, published as the
`othala` image) holds all of: the family-facing UI (tile dashboard, auth pages,
admin UI), the Hydra challenge handlers (login, consent, logout), and the OIDC
client registrar. The app runs in the same pod as Kratos, Hydra, and Postgres.
The standalone consent service and the shell apply-runner are retired. There is
no separate consent quadlet, admin quadlet, or LDAP-bridge quadlet in the
deployed pod -- everything routes through the one portal process.

The registrar (`registerAllClients` / `registerManifests` in
`register-clients.ts`) runs on portal startup and reconciles on `SIGHUP`. It is
not a route or a separate daemon. CI exercises it via the e2e harness. After
changing manifests, operators trigger a reload with a one-shot reconcile command
(`just dag-reload-clients <host>`) that deploys the current catalog manifests to
the host and sends `SIGHUP` to the portal process.

Per client, the registrar decides create vs. update by probing
`getOAuth2Client`: a 404 means create (`createOAuth2Client`), anything else
means update (`setOAuth2Client`). It never issues a delete. This is a
deliberate scope boundary, not an oversight: the registrar is a reconciler for
the manifest set it is given, and removing a client from Hydra is judged an
operator action with enough blast radius (an in-flight token, a still-linked
consumer) that it should never happen implicitly as a side effect of a manifest
going missing from `MANIFEST_DIR`.

## Consequences

- One process to deploy, monitor, and update instead of three. The blast radius
  of a portal deployment is higher (it touches more behavior), but the
  operational surface is smaller.
- The portal has direct network access to Kratos admin (`:4434`) and Hydra admin
  (`:4445`) over the pod-internal network. This is an access grant, not just a
  simplification; see the trust boundary discussion in ARCHITECTURE.md.
- No Workers adapter. The portal is a Node process. Deploying it requires a
  container runtime (podman/docker), not Cloudflare credentials. That is the
  expected trade for homelab use.
- The registrar runs on startup and on `SIGHUP`. The startup run is safe: it
  only creates or updates clients declared in `MANIFEST_DIR`; it does not
  delete clients present in Hydra but absent from the current manifest set.
  Removal is an explicit operator action (`hydra clients delete <id>` plus
  removing the corresponding secret from the secrets store).
- **Designed consequence, observed live:** because the registrar never
  deletes, decommissioning a service's OIDC client leaves a ghost registration
  in Hydra until an operator removes it by hand. The deployed instance carries
  exactly this case today -- a service was converted from OIDC to a
  forward-auth access pattern, its manifest dropped the `oidc:` block, and the
  registrar correctly stopped touching it, but the old Hydra client and its
  secret remain until the operator runs the explicit delete. This is tracked
  as deploy-repo drift with its own closure criterion, not as a registrar bug.

## Alternatives considered

- **Keep the consent service separate.** No benefit at single-tenant family
  scale. The service boundary was real overhead (two images, two quadlets, one
  network hop) for a handler that is stateless request/response.
- **Keep the Workers adapter.** Blocked by the admin port access constraint.
  A Worker cannot reach pod-internal addresses. This was discovered during the
  feasibility phase and corrected before any Workers-specific code was written.
- **Shell-script OIDC registration (apply-clients.sh).** Replaced because it
  required the `hydra` CLI binary in the deploy environment and was not
  type-checked against the manifest schema. The TypeScript registrar validates
  manifest structure before calling the SDK; errors surface at registration time
  with precise field names.
- **Delete-on-reconcile (full sync, including removal).** Rejected: an
  automatic delete tied to a manifest going missing is one accidental
  `rm`/typo away from revoking a live client's tokens. Removal stays a
  deliberate, explicit operator action instead of an implicit side effect of
  the reload.
