![hero](hero.svg)

# Othala

[![pipeline](https://gitlab.com/dunn.dev/othala/badges/main/pipeline.svg)](https://gitlab.com/dunn.dev/othala/-/pipelines)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![built with GitLab](https://img.shields.io/badge/built%20with-GitLab-fc6d26?logo=gitlab)](https://gitlab.com/dunn.dev/othala)

A reference deployment with no roadmap, no support and no compatibility promise.

Othala is a running Ory deployment: **Kratos** for identity, **Hydra** for OAuth2/OIDC, and one
TypeScript application that supplies the parts Ory deliberately leaves to the integrator.

Ory ships no login UI, no consent UI, and no authorization model. Hydra will not issue a token until
something tells it who the subject is and what they may have; Kratos holds groups on an identity but
never decides what they mean. Those decisions are the integration, and this repository is a worked
example with the reasoning kept next to the code.

The app in `portal/` (Astro Node SSR) provides:

- **the login and consent providers** Hydra calls on every authorization request;
- **the access gate** that decides whether a person may enter a given app, fail-closed;
- **the id_token claims builder** that turns group membership into the claims apps read;
- **a forward-auth endpoint** so apps with no OIDC support sit behind the same session and the same
  groups;
- **an OIDC client registrar** that reconciles Hydra's client list from per-app manifest files, so
  adding an app, logo included, needs no image rebuild;
- **an admin surface** for identities, groups, and OAuth2 clients, served on the public listener and
  gated by an admin session.

Passkeys are the primary credential; email code and password are the fallbacks. Everything is
configured through `OTHALA_*` environment variables, so one image serves any instance
(see [`.env.example`](.env.example) for the full contract).

## Run it

### The whole stack

`e2e/` runs the shipped compose deployment, [`deploy/example/`](deploy/example/), with a mail catcher and
test hostnames on the reserved domain `othala.test`, then a smoke matrix and a Playwright suite. It
touches no real DNS.

```sh
cd e2e
AUTH_VERSION=latest bash validate.sh
```

Needs a Docker- or Podman-compatible compose runtime. See [`e2e/README.md`](e2e/README.md).

### The app alone

To work on the UI without the Ory substrate, run the dev server. The dashboard is built from the
manifests in `/etc/othala/apps`, so it renders empty unless that directory exists:

```sh
cd portal
npm install
npm run dev   # http://localhost:4321
```

Unset `OTHALA_*` values fall back to dev defaults with a warning. OIDC and consent need the full stack.

## An app is a manifest

One `<slug>.yaml` per app, read at request time from `apps/` under the content root, carrying up to three blocks:
`presentation:` (tile metadata and the entry binding), `oidc:` (the OAuth2 client forwarded to
Hydra), and `consent:` (roles, the group-to-role map, claim emission).

[`e2e/content/apps/grafana.yaml`](e2e/content/apps/grafana.yaml) and
[`e2e/content/apps/audiobookshelf.yaml`](e2e/content/apps/audiobookshelf.yaml) are the annotated spec.
`npm run lint:manifests` (in `portal/`) checks a content directory.

## Where to look next

- [`ARCHITECTURE.md`](ARCHITECTURE.md): how the pieces fit and why.
- [`DEPLOY.md`](DEPLOY.md): what a deployment owns, its topology, and upgrades.
- [`SECURITY.md`](SECURITY.md): the trust boundary, controls, accepted risks; report vulnerabilities privately.
- [`.env.example`](.env.example): the runtime contract, every variable annotated.
- [`site/src/content/docs/guides/`](site/src/content/docs/guides/): illustrated guides at [othala.dunn.dev](https://othala.dunn.dev).
- [`CHANGELOG.md`](CHANGELOG.md): release notes and config changes per tag.

## Contributing

Corrections are welcome: a false statement, a dead link, a config that does
not do what it claims. Feature requests and changes that add configuration surface for a different
deployment are not taken; fork it.

## License

MIT. See [`LICENSE`](LICENSE).
