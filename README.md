![hero](hero.svg)

# Othala

[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE) ![built with GitLab](https://img.shields.io/badge/built_with-GitLab-FC6D26?logo=gitlab)

Ory for your home. Othala is a self-hosted Ory substrate for a personal estate: the on-prem, family-scale analog to Ory Network. One all-TypeScript application (Astro Node SSR) fronts upstream Ory Kratos (identity) + Hydra (OAuth2/OIDC) + Postgres. Passkey-first by design — passkeys are the primary credential; email code and password are fallback paths. WebAuthn security keys are supported too, but as a legacy second factor, not a peer to passkeys. A companion Go glauth-kratos LDAP bridge exists as a separate, currently-parked project (`gitlab.com/dunn.dev/kratos-ldap`) for adopters who need non-OIDC LDAP integration.

The name is the rune ᛟ *othala* (home, inheritance, the estate). Andrew's deployed instance runs on **dag.dunn.dev** (ᛞ *dagaz*, the threshold rune). The login screen renders the motif **ᛞ→ᛟ "door to home"**: through the door (dag), into the home (othala).

## What it is

One converged application, not a fleet of services:

- **The Othala app** (`portal/`, Astro Node SSR + TypeScript). It renders the Kratos self-service browser flows, acts as Hydra's login + consent + logout provider (Hydra ships no UI by design), holds the access gate and the id_token claims builder, runs the in-process revoke fan-out, and exposes admin endpoints on a separate loopback listener. It reads per-app manifests at runtime from a mounted directory (`MANIFEST_DIR`), so adding an app is a manifest drop, not an image rebuild. It runs as a Node process inside the SSO pod so Kratos's and Hydra's admin ports are reachable directly.
- **The Ory substrate** (Kratos + Hydra + Postgres). Kratos owns identity (login, recovery, settings, passkeys). Hydra owns OAuth2/OIDC. Single-source-of-truth identity in Kratos; OIDC is the primary presentation layer downstream.
The OSS project is **Othala**; the GitLab project is `dunn.dev/othala`. The app package is `@dunn.dev/othala-portal`; the image publishes at `registry.gitlab.com/dunn.dev/othala`. A companion LDAP bridge exists at `gitlab.com/dunn.dev/kratos-ldap` (Go, separate repo; currently parked).

## Built for us, open for you

We built Othala for our own home, and we run it in production now while iterating on it rapidly. We are making it open because others standing up Ory at household or small-estate scale may benefit from the same converged shape. It is currently opinionated toward our deployment; that opinionation is what keeps it small enough to run at home.

Two invitations:

- **Potential user, and this needs to be more generalized for your setup?** Please file an issue or a merge request. We are glad to generalize where it helps, and happy to take it further with you.
- **With Ory, and would like us to donate this upstream?** Please reach out. We would gladly take Othala to Ory upstream, with the generalization work that likely entails.

## Apps are manifests (runtime-driven)

An app is one unified `<slug>.yaml` manifest, read at request time from `MANIFEST_DIR` (default `/etc/portal/manifests`). One file can carry up to three namespace blocks:

- `presentation:` — the tile metadata (name, icon, description, URL, `auth_kind`, `access_group`). Read by `portal/src/lib/tiles.ts` to render the dashboard. An optional sibling `<slug>.md` is education content shown on the `/apps/<slug>` detail page.
- `oidc:` — the OAuth2/OIDC client fields forwarded to Hydra at registration. Read by `portal/src/lib/manifests.ts`.
- `consent:` — role and claim-emission shape, read by the app at consent time.

A manifest with only `presentation:` (a forward_auth, LDAP, or external tile with no Hydra client) is skipped by the OIDC loader. Because both loaders read the directory at runtime behind a 30-second cache, **adding or removing an app is a manifest-dir change with no image rebuild**.

The generic worked examples live in [`e2e/manifests/`](e2e/manifests/): `grafana` (OIDC + role mapping), `audiobookshelf` (OIDC), `jellyfin` (OIDC; the LDAP-bridge variant is in the parked kratos-ldap repo), `proxywatch` (forward_auth), `statuspage` (external). They double as the release-gate fixtures the smoke harness registers.

## Run it locally

The honest first-run path. Two modes, depending on what you want.

### Full stack (the e2e compose harness)

The complete worked example is the e2e harness. It stands up Postgres + Kratos + Hydra + Othala + Mailpit behind Caddy, renders the Ory configs, registers the example clients from `e2e/manifests/`, and runs the OIDC dance + smoke matrix. Everything runs on the RFC 6761 reserved test domain `othala.test`, so nothing touches a real domain. The LDAP bridge is a separate, currently-parked project (`gitlab.com/dunn.dev/kratos-ldap`); no e2e spec exercises it here.

```sh
cd e2e
AUTH_VERSION=latest bash validate.sh   # generates .env, renders configs, up, health-wait, smoke
```

Needs a Docker or Podman compose runtime. See [`e2e/README.md`](e2e/README.md) for the harness in detail.

### Portal-only dev (`npm run dev`)

To iterate on the Astro UI alone, run the dev server. The dashboard is built from the manifest directory, so **you must point `MANIFEST_DIR` at one or the dashboard renders empty.** The example manifests in `e2e/manifests/` are the easy choice:

```sh
cd portal
npm install
MANIFEST_DIR=../e2e/manifests npm run dev   # http://localhost:4321
```

Other `OTHALA_*` config falls back to safe dev defaults (with a warning), so the dev server comes up without the full Ory substrate. The OIDC and consent flows need Kratos + Hydra, so they only work in the full-stack mode above; portal-only dev is for the dashboard, self-service UI chrome, and `/apps/<slug>` pages.

```sh
npm test          # node --test over scripts/*.test.mjs (incl. fuzz suites)
npm run check     # astro check (type + content checks)
npm run build     # astro build + bundle the listener / admin / registrar
```

## Where to start

- **Cold-start orientation** (the anchor): [`ARCHITECTURE.md`](ARCHITECTURE.md). What the converged app holds, the load-bearing decisions, topology, and trust boundary.
- **Release / version state**: [`CHANGELOG.md`](CHANGELOG.md) and git tags. The only place a deployed version is asserted.
- **Deploy**: [`DEPLOY.md`](DEPLOY.md).
- **Network topology**: see the [Topology section of ARCHITECTURE.md](ARCHITECTURE.md#topology) (Envoy SNI router, SSO pod, app pods).

This README asserts no version. It is the front door.

## Layout

| Path | Contents |
|---|---|
| `docs/` | Architecture decision history (ADRs), Ory ecosystem survey, per-app integration, runbooks |
| `kratos/` | Kratos server config + identity schema |
| `hydra/` | Hydra server config |
| `portal/` | The Othala application (Astro Node SSR + TS): Kratos self-service flows, Hydra login/consent/logout challenge handlers, the access gate, claims builder, revoke fan-out, dual-listener admin endpoints, the runtime manifest loaders (`tiles.ts` + `manifests.ts`), and the OIDC client registrar. Publishes as the `othala` image. |
| `gitlab.com/dunn.dev/kratos-ldap` | glauth-kratos LDAP bridge (separate sibling repo, currently parked). Protocol adapter for non-OAuth clients needing LDAP. Not currently deployed. |
| `e2e/` | QEMU-CI smoke harness: compose stack + smoke scripts + gen-secrets + the generic example manifests (`e2e/manifests/`). Runs on carmine via the `e2e` CI job. |

## Architecture in brief

```mermaid
flowchart TB
  user([User browser / app client])

  subgraph CF[Cloudflare]
    dns[DNS records<br/>gray cloud, no proxy]
  end

  subgraph Home[Home network]
    router[Home router<br/>port-forward 443]
  end

  subgraph Host[SSO host]
    envoy[Envoy<br/>L4 SNI router 80/443]

    subgraph SsoPod[SSO pod]
      caddy[caddy-estate<br/>TLS + DNS-01]
      kratos[Kratos<br/>4433 public<br/>4434 admin]
      hydra[Hydra<br/>4444 public<br/>4445 admin]
      othala[othala app<br/>Astro Node SSR<br/>public + loopback admin listener]
      courier[Kratos courier]
      pg[(Postgres<br/>kratos + hydra DBs)]
    end

    subgraph JellyfinPod[jellyfin pod]
      bridge[glauth-kratos<br/>LDAPS 636]
      jellyfin[Jellyfin]
    end

    subgraph AppPods[app pods]
      apps[app containers<br/>caddy sidecar + container]
    end
  end

  user -->|DNS lookup| dns
  user -->|HTTPS 443| router
  router --> envoy
  envoy --> caddy
  envoy -.LDAPS off-path.-> bridge
  caddy --> kratos
  caddy --> hydra
  caddy --> othala
  caddy --> apps
  othala --> kratos
  othala --> hydra
  kratos --> pg
  hydra --> pg
  courier --> pg
  bridge --> kratos
  jellyfin -->|localhost:636| bridge
```

Cloudflare's role is DNS hosting + DNS-01 ACME via API. It is **not in the auth or app request path**. Visual language via [`@dunn.dev/reference`](https://gitlab.com/dunn.dev/reference) (tokens + site chrome).

> **Note:** The diagram shows the JellyfinPod LDAP bridge path as originally designed. The kratos-ldap bridge is shelved as of 2026-06-26; Cinema/Jellyfin now uses OIDC. The bridge repo (`gitlab.com/dunn.dev/kratos-ldap`) is parked for adopters who need it.

Full topology, request flows, auth patterns, image-pin table, and trust boundary: [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Validation

The Othala app (flows + login/consent + admin) is validated end-to-end through the QEMU-CI smoke harness (`e2e/`). Adversarial security review remediated HIGH + MEDIUM + LOW + architectural findings across two independent passes; fuzz harnesses caught two real bugs before merge (JWK algorithm allowlist). The fail-closed gate, revoke fan-out, and dual-listener boundary carry substantive unit tests.

The LDAP bridge is validated in its own repo (`gitlab.com/dunn.dev/kratos-ldap`; currently parked).

## Working conventions

- Push requires explicit human approval per action
- `CHANGELOG.md` and git tags are the only place release state is asserted; cold-start orientation is `ARCHITECTURE.md`
- Apply estate voice in external text: no em-dashes, direct phrasing, no filler
- `@dunn.dev/reference` is the single source for tokens and site chrome; do not redefine locally
- Secrets: sops + age, operator-managed and never committed

## License

MIT. See [`LICENSE`](LICENSE).

---

Built by Andrew Dunn with GitLab. The rune is ᛟ *othala* (home, inheritance); the door is ᛞ *dagaz* (the threshold).
