# Per-app OIDC integration runbook

First-deploy and first-user pilot guide. Covers the two-sided nature
of each integration: the Hydra-client side (manifest + client secret
in sops) and the RP-app side (entering issuer/client-id/secret/scopes
into the app's own config). Both sides must have the same secret or the
integration will fail silently in ways that look like provider errors.

This runbook covers OIDC-based integrations. For the forward-auth apps
(Navidrome/tune, Sonarr+Radarr/gather) see the `forward_auth` handling in
`ARCHITECTURE.md`. For Cinema's native clients
(Apple TV / Infuse), see [Cinema / Jellyfin](#cinema--jellyfin----oidc-with-a-jellyfin-local-password-for-native-clients).

> **Note for adopters:** every issuer/token/userinfo URL in this
> document uses `{YOUR_OTHALA_URL}` as a placeholder for your Othala
> instance's public FQDN (the value of `OTHALA_PUBLIC_URL`, no trailing
> slash). The author's instance runs on `dag.dunn.dev`; that hostname
> appears in example output only and is not a shared endpoint.

## Overview

- Issuer: `https://{YOUR_OTHALA_URL}/` (LB-2; non-changeable once any RP
  is wired).
- Discovery: `https://{YOUR_OTHALA_URL}/.well-known/openid-configuration`
- Authorization code flow for all interactive apps; `client_credentials`
  for `llm` (machine-to-machine only).
- Each app is a unified `<slug>.yaml` manifest read at runtime from
  `MANIFEST_DIR` (default `/etc/portal/manifests`; synced from this repo,
  worked examples in `dunn.dev/othala/e2e/manifests/`). A manifest can
  carry three namespace blocks: `presentation:` (tile metadata),
  `oidc:` (forwarded to Hydra), and `consent:` (role/claim shape read by
  the Othala app; never sent to Hydra).
- `client_id` equals the slug (e.g., `grafana`, `audiobookshelf`).
- Client secrets are sops-encrypted in your deploy repo (e.g.
  `pyinfra/secrets.enc.yaml`) under `<host>.<slug>_oidc_client_secret`.
  The same plaintext value must land in both Hydra (via
  `make dag-apply-clients`) and the RP app's own config. They are not
  linked automatically.
- Access groups: every interactive OIDC app has a corresponding Ory
  group named `access-<slug>`. The access gate denies tokens for
  users not in this group. Add users there before the login test.

## Generic procedure (once per new RP)

Do these steps in order. Steps 1-4 are PRE-DEPLOY verifiable (no live
app needed). Step 5 requires the RP app to be running.

**1. Generate a client secret.**

```sh
openssl rand -base64 32
```

Keep the value. You will need it in steps 2 and 4.

**2. Set the sops key.**

```sh
sops <your-deploy-repo>/pyinfra/secrets.enc.yaml
# Add or update: <host>.<slug>_oidc_client_secret: "<value from step 1>"
```

**3. Apply the Hydra client (Hydra side).**

```sh
cd <your-deploy-repo>
make dag-secrets HOST=<sso-host>   # writes the new sops entry into podman secrets
make dag-apply-clients HOST=<sso-host>
```

`dag-apply-clients` runs the Othala in-app registrar as a `--rm`
one-shot container on `dag.network` (the only network that can reach
Hydra's admin port 4445) and POST/PUTs each manifest's `oidc:` block from
`MANIFEST_DIR`. The container reads `<SLUG>_CLIENT_SECRET` from env, which
is sourced from the sops entry above. Exit 0 means Hydra accepted the
registration.

**4. Configure the RP app (app side).**

Enter into the app's own config:

| Field | Value |
|---|---|
| Issuer / OIDC discovery URL | `https://{YOUR_OTHALA_URL}/` |
| Client ID | `<slug>` (matches the manifest `client_id`) |
| Client secret | same plaintext from step 1 |
| Scopes | as listed in the manifest `scope:` field |
| Redirect URI | must match the manifest `redirect_uris:` exactly |

The exact config location varies per app; see the per-RP sections below.

After editing the app config, restart the app service before testing.

**5. Add the user to the access group (Ory side).**

The access gate checks group membership before issuing any token.
Add via the admin portal at `https://{YOUR_OTHALA_URL}/admin/users/<id>`.

**6. Test login (LIVE only).**

Navigate to the app URL, click "Sign in with SSO" (or equivalent),
complete the Kratos authn flow, confirm the app lands the user on the
correct page with the expected role. Check Hydra logs if the flow
aborts before redirect:

```sh
journalctl --user -u dag-hydra.service -n 100 | grep -i error
```

---

## Per-RP integrations

### observe -- Grafana (pilot: first)

- **App:** Grafana at `https://observe.dunn.dev`
- **Access group:** `access-observe`
- **Redirect URI:** `https://observe.dunn.dev/login/generic_oauth`
- **Scopes:** `openid email profile groups offline_access`
- **Back-channel logout URI:** `https://observe.dunn.dev/login/generic_oauth/logout`
- **Role claim:** `grafana_role` (array). Evaluated via JMESPath in Grafana config.

RP-side config location: `grafana.ini` section `[auth.generic_oauth]`,
or environment variables with `GF_AUTH_GENERIC_OAUTH_` prefix.

Minimum required keys:

```ini
[auth.generic_oauth]
enabled = true
name = Auth
client_id = observe
client_secret = <value from sops>
scopes = openid email profile groups offline_access
auth_url = https://{YOUR_OTHALA_URL}/oauth2/auth
token_url = https://{YOUR_OTHALA_URL}/oauth2/token
api_url = https://{YOUR_OTHALA_URL}/userinfo
redirect_uri = https://observe.dunn.dev/login/generic_oauth
use_pkce = false
allow_sign_up = true
role_attribute_path = contains(grafana_role[*], 'GrafanaAdmin') && 'GrafanaAdmin' || contains(grafana_role[*], 'Admin') && 'Admin' || contains(grafana_role[*], 'Editor') && 'Editor' || 'Viewer'
allow_assign_grafana_admin = true
groups_attribute_path = groups
backchannel_logout_enabled = true
```

PRE-DEPLOY verifiable: client registered in Hydra, secret matches,
`allow_assign_grafana_admin` is `true` for the admin role to take effect.

LIVE only: complete login, verify role shown in Grafana user profile.

---

### keep -- Vaultwarden (pilot: second)

- **App:** Vaultwarden at `https://keep.dunn.dev`
- **Access group:** `access-keep`
- **Redirect URI:** `https://keep.dunn.dev/identity/connect/oidc-signin`
- **Scopes:** `openid email profile groups offline_access`
- **Back-channel logout URI:** `https://keep.dunn.dev/identity/connect/oidc-logout` (set optimistically; verify in lab -- the wiki documents SLO without explicitly confirming back-channel)
- **Role claim:** `resource_access.keep.roles` (future, once PR #6158 merges upstream). Today: every SSO user is a regular member; admin uses local admin token.

RP-side config location: Vaultwarden environment variables, typically
set in the quadlet or compose file.

Minimum required env:

```sh
SSO_ENABLED=true
SSO_CLIENT_ID=keep
SSO_CLIENT_SECRET=<value from sops>
SSO_AUTHORITY=https://{YOUR_OTHALA_URL}/
SSO_SCOPES=groups offline_access
# Once PR #6158 lands upstream, also set:
# SSO_ROLES_ENABLED=true
# SSO_ROLES_TOKEN_PATH=resource_access.keep.roles
```

Verify against [Vaultwarden SSO wiki](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-SSO-support-using-OpenId-Connect)
at deploy for current env var names (the SSO module is under active
development; names may have shifted).

PRE-DEPLOY verifiable: client registered, env vars set, container
restart scheduled.

LIVE only: SSO sign-in completes, user appears in Vaultwarden user list.
Admin role requires PR #6158 to merge; until then, set admin in
Vaultwarden's local admin panel.

---

### forge -- GitLab

- **App:** Self-managed GitLab at `https://forge.dunn.dev`
- **Access group:** `access-forge` (enforced via `required_groups: ["forge-user"]` in gitlab.rb)
- **Redirect URI:** `https://forge.dunn.dev/users/auth/openid_connect/callback`
- **Scopes:** `openid email profile groups offline_access`
- **Back-channel logout URI:** `https://forge.dunn.dev/users/auth/openid_connect/logout`

RP-side config location: `gitlab.rb` on the forge side (or `gitlab.yml`
`omniauth:` for Helm/Kubernetes installs).

```ruby
gitlab_rails['omniauth_enabled'] = true
gitlab_rails['omniauth_allow_single_sign_on'] = ['openid_connect']
gitlab_rails['omniauth_sync_email_from_provider'] = 'openid_connect'
gitlab_rails['omniauth_auto_link_user'] = ['openid_connect']
gitlab_rails['omniauth_providers'] = [
  {
    name: 'openid_connect',
    label: 'Auth (dunn.dev)',
    args: {
      name: 'openid_connect',
      scope: ['openid', 'email', 'profile', 'groups', 'offline_access'],
      response_type: 'code',
      issuer: 'https://{YOUR_OTHALA_URL}/',
      discovery: true,
      client_auth_method: 'basic',
      client_options: {
        identifier: 'forge',
        secret: '<value from sops>',
        redirect_uri: 'https://forge.dunn.dev/users/auth/openid_connect/callback',
        gitlab: {
          groups_attribute: 'groups',
          required_groups: ['forge-user'],
          admin_groups: ['forge-admin'],
          external_groups: ['forge-external']
        }
      }
    }
  }
]
```

Run `gitlab-ctl reconfigure` after editing. Verify against the
[GitLab OIDC docs](https://docs.gitlab.com/administration/auth/oidc/)
at deploy; the `client_options.gitlab` sub-key is a GitLab extension
to the OmniAuth OIDC strategy and the key names may differ across
GitLab versions.

PRE-DEPLOY verifiable: client registered, `gitlab.rb` updated,
`reconfigure` exits 0.

LIVE only: SSO login completes, user's admin flag matches their group
membership.

---

### memory -- Immich

- **App:** Immich at `https://memory.dunn.dev`
- **Access group:** `access-memory`
- **Redirect URIs:** `https://memory.dunn.dev/auth/login` and `app.immich:/` (mobile)
- **Scopes:** `openid email profile groups offline_access`
- **Back-channel logout URI:** `https://memory.dunn.dev/api/oauth/logout` (v1.117+)
- **Role claim:** `immich_role` (string: `"admin"` or `"user"`). Read at user creation only; not re-synced on subsequent logins.

RP-side config location: Immich admin UI under Administration > OAuth,
or `IMMICH_OAUTH_*` environment variables.

Key settings (verify exact env names against [Immich OAuth docs](https://docs.immich.app/administration/oauth/)):

```sh
OAUTH_ENABLED=true
OAUTH_ISSUER_URL=https://{YOUR_OTHALA_URL}/
OAUTH_CLIENT_ID=memory
OAUTH_CLIENT_SECRET=<value from sops>
OAUTH_SCOPE=openid email profile groups offline_access
OAUTH_AUTO_REGISTER=true
# The role claim name must match what the Othala app emits at consent:
OAUTH_IMMICH_ADMIN_ROLE=admin  # value to match in immich_role claim
```

PRE-DEPLOY verifiable: client registered, env set or UI values saved.

LIVE only: first login provisions the user with the correct role.
Role is set once at creation; to change an existing user's role, use
the Immich admin UI directly.

---

### vault -- oCIS

- **App:** ownCloud Infinite Scale at `https://vault.dunn.dev`
- **Access group:** `access-vault`
- **Redirect URIs:** `https://vault.dunn.dev/oidc-callback` and `https://vault.dunn.dev/oidc-silent-redirect`
- **Scopes:** `openid email profile groups offline_access`
- **Back-channel logout URI:** `https://vault.dunn.dev/signin/v1/oidc-backchannel-logout`
- **Role claim:** `roles` (array). Values: `ocisAdmin`, `ocisSpaceAdmin`, `ocisUser`, `ocisGuest`.

RP-side config location: oCIS proxy service config (`proxy.yaml`) and
oCIS env variables. The proxy reads OIDC claims when
`PROXY_ROLE_ASSIGNMENT_DRIVER=oidc`.

Key env vars (verify against [oCIS proxy docs](https://doc.owncloud.com/ocis/next/deployment/services/s-list/proxy.html)):

```sh
PROXY_OIDC_ISSUER=https://{YOUR_OTHALA_URL}/
OCIS_OIDC_ISSUER=https://{YOUR_OTHALA_URL}/
PROXY_ROLE_ASSIGNMENT_DRIVER=oidc
PROXY_ROLE_ASSIGNMENT_OIDC_CLAIM=roles
PROXY_AUTOPROVISION_CLAIM_GROUPS=groups
# Client ID/secret used by oCIS internal services for machine-to-machine:
OCIS_OIDC_CLIENT_ID=vault
# client_secret: verify against oCIS docs whether this is needed for
# the proxy path or only for the IDP-internal service accounts.
```

PRE-DEPLOY verifiable: client registered, proxy config updated.

LIVE only: login completes, user's space appears, role reflects their
identity group (admin -> ocisAdmin, family -> ocisUser, etc.).

---

### larder -- Mealie

- **App:** Mealie at `https://larder.dunn.dev`
- **Access group:** `access-larder`
- **Redirect URI:** `https://larder.dunn.dev/login`
- **Scopes:** `openid email profile groups offline_access`
- **Back-channel logout URI:** `https://larder.dunn.dev/api/auth/oidc/logout` (set optimistically; verify in lab)
- **Role claim:** `groups` array. Values: `larder-admin` or `larder-user`. Login gated by `OIDC_USER_GROUP`.

RP-side config (env vars in the Mealie quadlet):

```sh
OIDC_AUTH_ENABLED=true
OIDC_CONFIGURATION_URL=https://{YOUR_OTHALA_URL}/.well-known/openid-configuration
OIDC_CLIENT_ID=larder
OIDC_CLIENT_SECRET=<value from sops>
OIDC_AUTO_REDIRECT=false
OIDC_GROUPS_CLAIM=groups
OIDC_USER_GROUP=larder-user
OIDC_ADMIN_GROUP=larder-admin
OIDC_USER_CLAIMS_UPDATE=true
```

Verify against [Mealie OIDC v2 docs](https://docs.mealie.io/documentation/getting-started/authentication/oidc-v2/)
at deploy; the OIDC env interface was overhauled in the v2 release and
var names are not stable across minor versions.

PRE-DEPLOY verifiable: client registered, env set, service restart.

LIVE only: login completes, household appears, admin user gets Mealie
admin badge.

---

### tailscale (external RP)

- **App:** Tailscale control plane at `https://login.tailscale.com`
- **Redirect URI:** `https://login.tailscale.com/a/oauth_response`
- **Scopes:** `openid email profile` (no `groups`; groups claim suppressed)
- **No back-channel logout** (Tailscale custom OIDC has no per-app session to revoke)
- **No access group enforcement** at the IDP; access is controlled in the Tailscale admin console

Tailscale tenant setup is a one-time operation, not a per-deploy step.
WebFinger for `*@dunn.dev` is served from the dunn.dev apex
(Cloudflare Pages function); the issuer URL is locked in at that time.
See `docs/apex-webfinger-followup.md` for the discovery path.

RP-side config: Tailscale admin console > Settings > OIDC. Enter:
- Issuer URL: `https://{YOUR_OTHALA_URL}/`
- Client ID: `tailscale`
- Client secret: value from sops

Roles and owner assignments are made inside Tailscale; the IDP delivers
identity only.

PRE-DEPLOY verifiable: client registered in Hydra, WebFinger response
returns the correct issuer.

LIVE only: user authenticates, Tailscale node approves.

---

### listen -- Audiobookshelf

- **App:** Audiobookshelf at `https://listen.dunn.dev`
- **Access group:** `access-listen`
- **Redirect URIs:** `https://listen.dunn.dev/auth/openid/callback` (web) and `https://listen.dunn.dev/auth/openid/mobile-redirect` (mobile)
- **Scopes:** `openid email profile groups offline_access`
- **Back-channel logout URI:** `https://listen.dunn.dev/auth/openid/logout` (v2.7+)
- **Role claim:** `groups` array. Values are the literal strings `admin`, `user`, or `guest` (hardcoded upstream; not configurable as of v2.x).

RP-side config location: Audiobookshelf admin UI under Settings >
Authentication. Verify exact field names against the
[Audiobookshelf OIDC guide](https://www.audiobookshelf.org/guides/oidc_authentication/)
at deploy.

Key fields:

```
Issuer URL:      https://{YOUR_OTHALA_URL}/
Client ID:       listen
Client secret:   <value from sops>
Scopes:          openid email profile groups offline_access
Group claim:     groups
Auto Register:   enabled
```

PRE-DEPLOY verifiable: client registered, fields saved.

LIVE only: login completes, user's role shown in Audiobookshelf matches
their identity group (admin -> `admin`, family/friends/kids -> `user`).

---

### library -- BookLore

- **App:** BookLore at `https://library.dunn.dev`
- **Access group:** `access-library`
- **Redirect URI:** `https://library.dunn.dev/api/auth/oidc/callback`
- **Scopes:** `openid email profile groups offline_access`
- **No back-channel logout** (not implemented in BookLore upstream as of v0.x)
- **Role claim:** none. BookLore ignores `groups`; admin is set inside BookLore only.

RP-side config: verify against [BookLore OIDC docs](https://booklore.org/docs/tools/user-management)
at deploy for current config keys. Expected fields:

```
Issuer URL:    https://{YOUR_OTHALA_URL}/
Client ID:     library
Client secret: <value from sops>
Scopes:        openid email profile groups offline_access
```

JIT user creation requires an admin to enable it in BookLore settings.
Enable that before the first login test or the user will see a 403.

PRE-DEPLOY verifiable: client registered, config saved.

LIVE only: login completes, user appears with `OIDC` badge in BookLore
user list. Admin role must be granted inside BookLore manually.

---

### llm -- vLLM (machine-to-machine only)

- **Flow:** `client_credentials` (no user, no id_token, no login UI)
- **No access group** (the access gate skips the access check for client_credentials)
- **No back-channel logout** (bearer tokens expire; revoke via Hydra admin API)

The llm client is for API consumers, not for interactive sign-in.
Caddy in front of vLLM introspects the bearer token at
`https://{YOUR_OTHALA_URL}/admin/oauth2/introspect`. A valid active token
admits the request; anything else is a 401.

Obtain a token:

```sh
curl -s -u 'llm:<client_secret>' \
  -d 'grant_type=client_credentials&scope=api' \
  https://{YOUR_OTHALA_URL}/oauth2/token | jq .access_token
```

Pass the token as `Authorization: Bearer <token>` to the vLLM API.

PRE-DEPLOY verifiable: client registered, token endpoint returns a
token for the correct `client_id`.

LIVE only: a token with `scope=api` reaches vLLM without a 401.

---

### listen, library, llm -- unconfirmed target apps

The manifest slugs `listen` (Audiobookshelf), `library` (BookLore), and
`llm` (vLLM) are confirmed by the manifest comments and consent blocks
above. No verification gap exists for these slugs; the uncertainty is
only in the RP-side config field names, which are stable enough to
link to upstream docs rather than reproduce here.

---

## Cinema / Jellyfin -- OIDC, with a Jellyfin-local password for native clients

**Updated 2026-06-26.** Cinema (Jellyfin) authenticates via OIDC using the
Jellyfin SSO plugin (ZL154, `jellyfin-plugin-sso`), client_id: `cinema`. This
is the same authorization-code flow as every other OIDC app in this runbook.
The Kratos/dag credential is the OIDC credential; it never enters Jellyfin
directly.

### Native clients (Infuse, Apple TV)

Native clients that cannot perform the OAuth browser redirect (Infuse, the Apple
TV Jellyfin client) use a **Jellyfin-local password**: a credential stored only
in Jellyfin's own user database. This is a separate, dedicated credential for
native-client use. The Kratos password is not shared with Jellyfin and is not
used here.

To set the Jellyfin-local password for a user:

1. Log in to Jellyfin as an admin (via the browser/OIDC path).
2. Go to Admin Dashboard, then Users, then select the user.
3. Set a password in the Jellyfin user settings panel.

The user then enters that Jellyfin-local password in Infuse or Apple TV.

### LDAP (shelved 2026-06-26)

A prior approach used the kratos-ldap LDAP bridge (`gitlab.com/dunn.dev/kratos-ldap`)
co-located in the Jellyfin pod to authenticate native clients over LDAPS. That
approach is shelved. Jellyfin no longer has the LDAP plugin configured; the
bridge is not deployed in the cinema pod. The kratos-ldap project is parked (not
deleted) and remains available to adopters who need non-OIDC LDAP integration.

### Verification

PRE-DEPLOY verifiable: the `cinema` OIDC client is registered in Hydra (the
`cinema.yaml` manifest has an `oidc:` block), the SSO plugin is installed in
Jellyfin, and the configured redirect URI matches the manifest entry.

LIVE only: browser login completes the OIDC flow and lands the user in the
correct Jellyfin library; native client login with the Jellyfin-local password
succeeds.

---

## Troubleshooting

**Redirect URI mismatch.** Hydra rejects the auth request with
`redirect_uri_mismatch`. The URI in the app config (including trailing
slash, scheme, and exact path) must byte-match the manifest
`redirect_uris:` entry. Check both sides. A common mistake is omitting
or adding a trailing slash.

**Secret mismatch between sides.** The RP app presents the client secret
to Hydra's token endpoint. If the value differs from what Hydra has
stored, the token exchange fails with `invalid_client`. Regenerate and
set the sops value, re-run `make dag-apply-clients`, and update the
app config. Both must come from the same sops plaintext.

**Missing access group.** The access gate returns an error if the
authenticating user is not a member of `access-<slug>`. Add the user to
the group via the admin portal before retesting. The group must exist in
Kratos; it is created by the Kratos init or by the admin UI -- it is not
auto-created on first login.

**Nonce / state validation failure.** If the app logs a nonce or state
mismatch after the redirect, the most common cause is a clock skew
between the SSO host and the client, or a redirect through an
intermediate that drops the state query parameter (e.g., a reverse
proxy rewriting the Location header). Check NTP sync on the SSO host
and ensure the proxy config passes query parameters unchanged.

**Back-channel logout returning 4xx.** For apps marked "verify in lab"
(`keep`, `larder`), a 4xx on the logout endpoint is expected if the
upstream has not implemented back-channel. Log the gap, fall back to
admin session revoke via the portal (`POST /admin/revoke-user`), and
open an upstream issue if the endpoint exists but returns an error.

## Related

- `ARCHITECTURE.md` -- issuer URL (LB-2), cookie domain (LB-4), subject types (LB-5)
- `MANIFEST_DIR` (`/etc/portal/manifests`) -- the runtime manifest set; worked examples in `e2e/manifests/`
- `docs/runbooks/secrets-rotation.md` -- break-glass if `secrets.system` is compromised
- `portal/src/lib/register-clients.ts` -- the in-app OIDC client registrar (replaces the legacy `dag-util` / `apply-clients.sh` runner)
- `DEPLOY.md` -- full promotion path including `make dag-apply-clients`
