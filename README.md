![hero](hero.svg)

# Othala

[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A reference deployment, not a product: no roadmap, no support, no compatibility promise.

Othala is a running Ory deployment: **Kratos** for identity, **Hydra** for OAuth2/OIDC, and one
TypeScript application that supplies the parts Ory deliberately leaves to the integrator.

Ory ships no login UI, no consent UI, and no authorization model. Hydra will not issue a token until
something tells it who the subject is and what they may have; Kratos will hold groups on an identity
but will never decide what they mean. Those decisions are the integration, and they are the part with
the fewest complete worked examples in the open. This repository is one, with the reasoning kept next
to the code.

The app in `portal/` (Astro Node SSR) provides:

- **the login and consent providers** Hydra calls on every authorization request;
- **the access gate** that decides whether a person may enter a given app, fail-closed;
- **the id_token claims builder** that turns group membership into the claims apps actually read;
- **a forward-auth endpoint** so apps with no OIDC support sit behind the same session and the same
  groups;
- **an OIDC client registrar** that reconciles Hydra's client list from per-app manifest files, so
  adding an app is a file drop rather than an image rebuild;
- **an admin surface** for identities, groups, and OAuth2 clients, on a listener that is not on the
  network.

Passkeys are the primary credential; email code and password are the fallbacks. Everything is
configured through `OTHALA_*` environment variables, so one image serves any instance
(see [`.env.example`](.env.example) for the full contract).

Read it, copy it, lift whole files out of it. That is what it is for.

## Run it

### The whole stack

The compose harness in `e2e/` stands up Postgres, Kratos, Hydra, the app, and a mail catcher, renders
the Ory configs, registers the example OIDC clients, and runs a smoke matrix plus a Playwright suite
against the result. It runs entirely on the reserved test domain `othala.test`, so it touches no real
DNS.

```sh
cd e2e
AUTH_VERSION=latest bash validate.sh
```

Needs a Docker- or Podman-compatible compose runtime. See [`e2e/README.md`](e2e/README.md).

### The app alone

To work on the UI without the Ory substrate, run the dev server. The dashboard is built from the
manifests in `/etc/portal/manifests`, so it renders empty unless that directory exists:

```sh
cd portal
npm install
npm run dev   # http://localhost:4321
```

Unset `OTHALA_*` values fall back to dev defaults with a warning. OIDC and consent need Kratos and
Hydra, so use the full-stack mode above.

```sh
npm test          # vitest run: src/lib/*.test.ts + scripts/*.test.mjs, incl. fuzz suites
npm run check     # astro check
npm run build     # astro build + the listener, admin, and registrar bundles
```

## An app is a manifest

One `<slug>.yaml` per app, read at request time from the manifest directory, carrying up to three blocks:
`presentation:` (tile metadata and the entry binding), `oidc:` (the OAuth2 client forwarded to
Hydra), and `consent:` (roles, the group-to-role map, claim emission).

[`e2e/manifests/grafana.yaml`](e2e/manifests/grafana.yaml) and
[`e2e/manifests/audiobookshelf.yaml`](e2e/manifests/audiobookshelf.yaml) are the annotated spec.
Every field's constraint and enforcer is a comment on the line, so the documented behaviour and the
tested behaviour are the same file. `validateClients` and `lintManifests`
(`portal/src/lib/manifests.ts`, `portal/src/lib/manifest-lint.ts`) are the enforcement; `npm run
lint:manifests` (in `portal/`) checks a manifest directory.

## Repository map

| Path | Contents |
|---|---|
| `portal/` | The application: Kratos self-service flows, Hydra login/consent/logout providers, access gate, claims builder, manifest loaders, client registrar, admin pages, dual listener |
| `kratos/` | Kratos config template, identity schema, the recovery-gate hook |
| `hydra/` | Hydra config template |
| `caddy/` | Reverse-proxy integration examples: a worked `Caddyfile` and reusable `caddy/snippets/` |
| `e2e/` | Compose harness, smoke script, Playwright specs, example manifests |
| `site/` | Source for the published guides |
| `docs/runbooks/` | Operator runbooks: recovery, cookie rotation, lost device, backup, secrets rotation |
| `scripts/` | The canonical Ory-config render and the repo gates |

## Where to look next

- [`ARCHITECTURE.md`](ARCHITECTURE.md): how the pieces fit and why. Topology, trust boundary,
  access model, the forward-auth request path, client registration.
- [`.env.example`](.env.example): the runtime contract, every variable annotated.
- [`DEPLOY.md`](DEPLOY.md): the deploy shape and the promotion path.
- [`site/src/content/docs/guides/`](site/src/content/docs/guides/): the longer operator guides,
  illustrated at [othala.dunn.dev](https://othala.dunn.dev) (architecture, login flow, trust boundary).
- [`SECURITY.md`](SECURITY.md): report vulnerabilities privately, never in a public issue.
- [`CHANGELOG.md`](CHANGELOG.md) and the git tags: the only place release state is asserted.

## Copying this

Copy freely; it is MIT.

Corrections are wanted: a statement here that is false, a dead link, a config that does not do what
it claims. Those are bugs, and an issue or merge request for one is welcome. Feature requests and
changes that add configuration surface to fit a different deployment are not taken, even when the
patch is good. Fork it; that is what the licence is for.

## License

MIT. See [`LICENSE`](LICENSE).
