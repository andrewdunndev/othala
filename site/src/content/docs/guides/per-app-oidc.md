# Per-app OIDC

How the apps on this instance are wired to Othala over OIDC, and what it takes
to wire a new one. This is `dag.dunn.dev`'s own runbook, published because the
per-app quirks are the expensive part and there is no reason to make anyone
else rediscover them.

Every URL below is this instance's. `https://dag.dunn.dev/` is the issuer here
and is not a shared endpoint; if you are reading this to copy it, substitute
your own and keep reading: the interesting content is the per-app notes, not
the hostname.

Not every app speaks OIDC. Two other paths exist and are covered elsewhere:
Caddy `forward_auth` into the portal's session gate (ADR 15), and a
service-local password for native clients that cannot run a browser redirect
(ADR 01). An app that can do none of the three does not get connected.

## The shape

- **Issuer:** `https://dag.dunn.dev/`. Non-changeable once any RP is wired
  (`ARCHITECTURE.md`, LB-2).
- **Discovery:** `https://dag.dunn.dev/.well-known/openid-configuration`
- **Flow:** authorization code for every interactive app. No implicit, no
  device code (golden path §4).
- **One manifest per app**, `<slug>.yaml`, read at runtime from `MANIFEST_DIR`
  (default `/etc/portal/manifests`). Adding an app is a manifest drop, not an
  image rebuild. A manifest carries up to three namespace blocks:
  `presentation:` (tile metadata and the access binding), `oidc:` (forwarded to
  Hydra), and `consent:` (role and claim shape, read by the portal, never sent
  to Hydra).
- **`client_id` equals the slug.** `keep`, `forge`, `memory`, and so on.
- **Client secrets** are sops-encrypted in the deploy repo under
  `<slug>_oidc_client_secret` and delivered to the portal as
  `<SLUG>_CLIENT_SECRET`. The same plaintext must land in both Hydra and the RP
  app's own config; nothing links the two automatically, and a mismatch fails
  as `invalid_client` at the token exchange, which reads like a provider error.
- **Two groups per service, and they do different jobs.** `<svc>-access` is
  **entry**: hold it and you get in, and that is true of everyone, admins
  included. `<svc>-admin` is **role only**: it elevates a member who is already
  admitted and it admits nobody on its own. Nothing is derived from anything
  else, so "can this person get in?" is answered by looking at one group. The
  full model is ADR 09 and `docs/access-model.md`.

That last point has a concrete shape in the manifest, and it is the one thing
worth getting right:

```yaml
presentation:
  access:
    - grafana-access      # ENTRY. Only the access group, ever.

consent:
  group_role_map:
    grafana-admin: admin  # ROLE. Both groups appear here.
    grafana-access: viewer
```

`presentation.access` is an OR-list evaluated by the access gate
(`portal/src/lib/gate.ts`, over the list parsed by
`portal/src/lib/access-groups.ts`). Putting `<svc>-admin` in it is exactly what
would make an admin group grant entry on its own, which is the mechanism the
converged model abolished. An identity holding only `<svc>-admin` is denied at
the gate before any claim is composed: that is a misconfigured identity, not a
supported shortcut.

Group **names** are convention. A group's type comes from which manifest key
binds it, never from its spelling. `portal/src/lib/group-registry.ts` records
why name-based inference was retired, and nothing in the loader enforces the
suffix style.

<figure class="diagram">
  <img src="/diagrams/group-binding-decision.svg" alt="Three columns. The identity holds groups in metadata_admin.groups, which is admin-API only. The manifest binds them twice — presentation.access as the entry binding, consent.group_role_map as the role binding. The code then decides: the access gate admits on the entry binding, and lookupRole resolves the role from the highest-ranked match. Holding only the admin group admits nobody, and a group no manifest binds grants nothing.">
  <figcaption class="diagram-caption">The identity holds · the manifest binds · the code decides</figcaption>
</figure>

## Wiring a new RP

Steps 1 to 4 are verifiable without the app running. Step 5 needs it up.

**1. Generate a client secret.**

```sh
openssl rand -base64 32
```

**2. Put it in sops** in the deploy repo as `<slug>_oidc_client_secret`, and
provision it onto the host. `DEPLOY.md` is the authority for the deploy-plane
commands; they live in the deploy repo and change independently of this one.

**3. Write the manifest** as `<slug>.yaml` under the deploy plane's catalog,
with `presentation.access` naming only `<svc>-access` and `consent.group_role_map`
naming both groups. `e2e/manifests/grafana.yaml` in this repo is the fully
worked reference and is the fixture the access model is asserted against.

**4. Register the client with Hydra.**

```sh
just dag-reload-clients <host>
```

That runs the portal's own registrar (`portal/src/lib/register-clients.ts`) as a
`--rm` one-shot on the network that can reach Hydra's admin port, reading each
manifest's `oidc:` block from `MANIFEST_DIR` and `<SLUG>_CLIENT_SECRET` from
env. It creates or updates and **never deletes** (ADR 02), so retiring a service
leaves a ghost registration in Hydra until an operator removes it by hand.

**5. Configure the RP** with the issuer, client id, client secret, the scopes
from the manifest, and a redirect URI that byte-matches a `redirect_uris:`
entry. Restart the app.

**6. Grant the access group.** The gate checks membership before any token is
issued. Add the person to `<svc>-access` from the admin UI. An admin who will
also administer the app gets `<svc>-admin` **as well**, not instead.

**7. Log in.** If the flow dies before the redirect, Hydra's log is where it
says why.

## Worked example: Grafana

`e2e/manifests/grafana.yaml` is the complete, generic, copyable version, and it
is exercised by CI rather than by prose, so it cannot rot silently. It is the
role-mapping example: a JMESPath role attribute (`grafana_role`), a `groups`
claim, and a group-to-role map with three declared roles of which one is
reachable only by per-client override.

Two things in that file are worth reading even if you never run Grafana. The
comment on `presentation.access` explains why `grafana-admin` is absent, and
the comment on `consent.roles` explains why the declaration order is descending
privilege: `lookupRole` (`portal/src/lib/claims.ts`) reads a role's index as its
rank and keeps the highest rank matched across the identity's whole group set,
which is what makes resolution independent of the order the groups happen to be
stored in.

RP side, the minimum for Grafana's `[auth.generic_oauth]`:

```ini
[auth.generic_oauth]
enabled = true
client_id = grafana
client_secret = <value from sops>
scopes = openid email profile groups offline_access
auth_url = https://dag.dunn.dev/oauth2/auth
token_url = https://dag.dunn.dev/oauth2/token
api_url = https://dag.dunn.dev/userinfo
use_pkce = false
allow_sign_up = true
allow_assign_grafana_admin = true
groups_attribute_path = groups
backchannel_logout_enabled = true
role_attribute_path = contains(grafana_role[*], 'GrafanaAdmin') && 'GrafanaAdmin' || contains(grafana_role[*], 'Admin') && 'Admin' || contains(grafana_role[*], 'Editor') && 'Editor' || 'Viewer'
```

`allow_assign_grafana_admin` must be `true` or the admin role resolves to
org-admin only.

## The clients on this instance

Eight OIDC clients, all first-party, all `skip_consent: true` (ADR 10). The
catalog manifests in the deploy plane are the enforcing artifact and hold the
current redirect URIs, scopes and role maps; what follows is the part that is
not derivable from a manifest: the RP-side quirk that cost time to find.

| Slug | App | The quirk |
|---|---|---|
| `keep` | Vaultwarden | Role-to-claim mapping is not in mainline yet. Every SSO user is a regular member; the admin console uses Vaultwarden's own local admin token, not OIDC. The manifest pre-stages `resource_access.keep.roles` so flipping the app env is the only change when upstream lands it. The SSO module moves fast, so check the current env var names against the Vaultwarden SSO wiki at deploy. |
| `forge` | GitLab | Groups are read through GitLab's OmniAuth extension keys, not standard OIDC: `groups_attribute`, `required_groups`, `admin_groups`. Note that `required_groups` names GitLab's own token (`forge-user`), which is emitted in the claim, and is **not** the Kratos entry group. Entry is still `forge-access` at the gate. `gitlab-ctl reconfigure` after editing `gitlab.rb`. |
| `memory` | Immich | The role claim is read **at user creation only** and never re-syncs. Changing an existing user's role means doing it in Immich's admin UI; re-logging in will not fix it. Mobile has its own redirect URI. |
| `larder` | Mealie | Login is gated on the app side too: `OIDC_USER_GROUP` must match a value the portal actually emits. Mealie is also the sole app that re-matches on `preferred_username` every login with no `sub` fallback, so a username change orphans the account (ADR 04). The OIDC env interface was overhauled at v2 and names are not stable across minors. |
| `listen` | Audiobookshelf | The role names are hardcoded upstream as the literal strings `admin`, `user`, `guest`, so the portal emits those literals rather than group names. They collide with the identity vocabulary; the collision stays scoped because the app only accepts id_tokens with its own audience. |
| `cinema` | Jellyfin | Browser login is OIDC via the ZL154 plugin. There is **no back-channel logout** (not implemented upstream), so logout falls back to admin session revoke plus Jellyfin's own token expiry. Native clients are a separate path, below. |
| `prompt` | Open WebUI | Needs `ENABLE_OAUTH_ROLE_MANAGEMENT=true` and `OAUTH_ROLES_CLAIM=groups` on the RP, and `ENABLE_LOGIN_FORM=false` to make it SSO-only. No back-channel logout upstream. |
| `infer` | LiteLLM | Two surfaces with different auth. `/v1/*` is bearer-key authenticated and Hydra is not in that path at all; `/ui/*` is layered: a Caddy `forward_auth` perimeter on `infer-access`, then LiteLLM's own OIDC against Hydra, reusing the session from the first round-trip so it is one login. LiteLLM resolves roles by set-intersection over the raw group names, not the mapped role tokens, which is worth knowing before debugging a role that will not stick. |

**`observe` is not on this list and used to be.** It was a Grafana OIDC client;
the live service is now HyperDX behind `forward_auth` on `observe-access`, with
no Hydra client and no `oidc:` block in its manifest. The deploy plane records
the old Hydra registration as a ghost awaiting a manual de-register, for the
reason ADR 02 gives: the registrar creates and updates, never deletes.

## Not OIDC

**Forward-auth apps.** Apps with no usable OIDC client sit behind Caddy
`forward_auth` calling the portal with a required group as a query parameter.
The status contract is deliberate and is the whole design: 401 only for "no
usable session", fail-closed 403 for everything else. ADR 15 owns it, including
why `session.whoami` must stay `aal1`.

<figure class="diagram">
  <img src="/diagrams/forward-auth-request-path.svg" alt="A browser carrying the apex-scoped Kratos session cookie reaches the estate edge and then the service's own Caddy, which issues a sub-request to the portal's /api/forward-auth endpoint with the required group as a query parameter before proxying anything. The portal verifies the session cookie, re-resolves the identity through the Kratos admin API because group membership is absent from whoami, and answers 200, 401 or 403. Caddy proxies only on 200, setting an identity header from the server-verified session id; the app itself sees only that header.">
  <figcaption class="diagram-caption">One sub-request decides the request, before the app ever sees it</figcaption>
</figure>

**Jellyfin's native clients.** Infuse and the Apple TV client cannot run the
OAuth browser redirect, so they use a **Jellyfin-local password**: a credential
stored in Jellyfin's own user database, set by an admin in Jellyfin's user
settings. It is not the Kratos password and the two are never shared. This is
load-bearing, not a fallback waiting to be simplified away (ADR 01).

**The LDAP bridge is not this.** A glauth-to-Kratos bridge at
`gitlab.com/dunn.dev/kratos-ldap` was built for exactly this native-client
problem and was retired 2026-06-29 having never run in production. It is an
**unmaintained reference**: readable, copyable, not deployed, not maintained,
and not an option being offered. Jellyfin has no LDAP plugin configured and no
bridge in its pod.

**External tiles.** Some tiles on the portal point at services with their own
auth entirely (a hosted password vault, for one). They carry an access group
for tile visibility and nothing else.

## Troubleshooting

**Redirect URI mismatch.** Hydra answers `redirect_uri_mismatch`. The URI in
the app config must byte-match a manifest `redirect_uris:` entry, scheme, path
and trailing slash included. A trailing slash is the usual culprit.

**`invalid_client` at the token exchange.** The RP is presenting a different
secret than Hydra holds. Both sides must come from the same sops plaintext:
re-set the sops value, re-run the registrar, and update the app config.

**The user is denied and you are sure they should not be.** Check the entry
group, not the admin group. Entry comes from `<svc>-access` and from nothing
else; an identity holding only `<svc>-admin` is denied before any claim is
composed, and that is working as designed. Membership is a string in the
identity's `metadata_admin.groups`, writable only through the Kratos admin API,
so nothing appears on first login and there is no self-service path to it.

**The role is wrong but the login works.** That is the `group_role_map` and the
claim shape, not the gate. Check what the app expects to read (the per-app
quirks above are mostly this) and remember that some apps read the role once at
account creation and never again.

**Nonce or state validation failure after the redirect.** Usually clock skew
between the host and the client, or an intermediate proxy dropping the `state`
query parameter while rewriting `Location`.

**Back-channel logout returns 4xx.** Expected for the apps whose upstream has
not implemented it. Fall back to admin session revoke from the portal, and open
an upstream issue only if the endpoint exists and errors.

## Related

- `docs/access-model.md`: the access-binding layer in full; the code cites it
  by section number.
- ADR 09 (access model), ADR 10 (skip-consent), ADR 15 (forward-auth gate).
- `e2e/manifests/`: the generic worked examples, exercised by CI.
- `ARCHITECTURE.md`: issuer URL (LB-2), cookie domain (LB-4), subject types (LB-5).
- `DEPLOY.md`: the promotion path and the deploy-plane commands.
- `portal/src/lib/register-clients.ts`: the in-app OIDC client registrar.
