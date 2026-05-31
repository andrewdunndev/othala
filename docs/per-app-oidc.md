# Per-app OIDC integration

The role/claim contract for each app in the homelab. This is the
operator-facing reference for what each app reads from the id_token,
what role tiers it actually supports, and where per-resource ACLs live
(those are not driven by claims).

The consent service reads each `hydra/clients/<app>.yaml` `roles:` and
`group_role_map:` blocks and emits the per-app claim shape into the
id_token at consent acceptance time. Resolution order: a non-empty
`metadata_admin.roles[<app>]` override wins; otherwise the first
identity group with a `group_role_map` entry maps to a role.

## OIDC clients

| App      | client_id  | App / upstream    | OIDC method              | Role tiers              | JIT? | Group claim shape                              | Per-resource ACL location | Back-channel logout | Notes |
|----------|------------|-------------------|--------------------------|-------------------------|------|------------------------------------------------|---------------------------|--------------------|-------|
| keep     | keep       | Vaultwarden       | authorization_code + PKCE| admin, user             | yes  | `groups: [...]` and `resource_access.keep.roles: [...]` once upstream lands | Org collections inside Vaultwarden | yes (set; verify in lab) | Mainline does not yet have role mapping; PR #6158 tracks. Today every login is regular member. Admin uses local admin token. |
| larder   | larder     | Mealie            | authorization_code       | admin, user             | yes  | `groups: ["larder-admin", "larder-user"]`      | Households, recipes inside Mealie | yes (set; verify in lab) | Two-role only. Login gated by OIDC_USER_GROUP. |
| listen   | listen     | Audiobookshelf    | authorization_code       | admin, user, guest      | yes  | `groups: ["admin"\|"user"\|"guest"]`             | Library access inside Audiobookshelf | yes (v2.7+) | Hardcoded role names upstream (issue #2878). guest tier defined but unused. |
| cinema   | cinema     | Jellyfin (browser SSO plugin) | authorization_code | admin, user      | yes  | `groups: ["jellyfin-admin"\|"jellyfin-user"]`   | Library/folder ACLs inside Jellyfin | no (plugin TBD) | Native clients use LDAP via the bridge, same identity, same memberOf. |
| memory   | memory     | Immich            | authorization_code (web + mobile redirect) | admin, user | yes | `immich_role: "admin"\|"user"` plus `groups: [...]` | Album sharing inside Immich | yes (v1.117+) | Role read on user creation only; not re-synced. |
| vault    | vault      | oCIS              | authorization_code       | admin, spaceadmin, user, guest | yes | `roles: ["ocisAdmin"\|"ocisSpaceAdmin"\|"ocisUser"\|"ocisGuest"]` plus `groups: [...]` | Space-level ACLs inside oCIS | yes | Richest role tiering of any app. Group provisioning supported. |
| library  | library    | BookLore          | authorization_code + PKCE| admin (local-only), user | manual (admin must enable) | `groups: [...]` (ignored upstream) | Library access inside BookLore | no | Admin set inside BookLore; OIDC does not drive role. Effectively single-tier from claims. |
| forge    | forge      | GitLab            | authorization_code       | admin, user, external   | yes  | `groups: ["forge-admin"\|"forge-user"\|"forge-external"]` | Project Maintainer/Developer/etc inside GitLab | yes (v15.4+) | required_groups gates login; admin_groups elevates to instance admin. |
| observe  | observe    | Grafana           | authorization_code       | admin (GrafanaAdmin), editor, viewer | yes | `grafana_role: ["GrafanaAdmin"\|"Admin"\|"Editor"\|"Viewer"]` plus `groups: [...]` | Folder/dashboard ACLs inside Grafana | yes (v10.2+) | role_attribute_path JMESPath in app config. allow_assign_grafana_admin=true required for instance admin. |
| tailscale| tailscale  | Tailscale         | authorization_code (no PKCE) | (none — identity only) | n/a (Tailscale provisions on its side) | none — `groups` claim suppressed | Roles/owners assigned inside Tailscale admin console | no | Custom OIDC has no group/role provisioning per upstream KB. |
| llm      | llm        | vLLM              | client_credentials       | (none — bearer token)   | n/a  | none — no id_token issued                      | n/a (binary admit/deny in Caddy via Hydra introspect) | n/a | Static API key style; no per-user role. |

The "Back-channel logout" column tracks whether the app accepts a
signed OIDC back-channel logout token at the configured
`backchannel_logout_uri`. When the column says "no" or "TBD", admin-
driven session revoke (`POST /admin/revoke-user` on the consent
service) drops the Kratos session but the app's local session
persists until its own cookie expires. Apps marked "verify in lab"
have the URI set optimistically; lab smoke tests will confirm.

## Forward auth (no Hydra client)

Forward auth gates traffic at Caddy by calling Kratos `/sessions/whoami`
plus optional group checks. There is no id_token in the picture, so
nothing in `hydra/clients/` applies. Admin/non-admin distinction here
is binary: the user either passes the group check or they don't.

| App     | App / upstream    | Header / mechanism                 | Role tiers from claims | Group enforcement |
|---------|-------------------|------------------------------------|------------------------|-------------------|
| tune    | Navidrome         | `Remote-User` from Caddy after Kratos whoami; `ND_REVERSEPROXYUSERHEADERNAME` on Navidrome side | none — first proxy user becomes Navidrome admin once, others are regular users | `access-tune` checked in Caddy snippet |
| gather  | Sonarr / Radarr / Prowlarr | Caddy forward_auth → Kratos `/sessions/whoami` | none — *arr admin is a local concept | `access-gather` checked in Caddy snippet |

The Subsonic API path (`/rest/*`, `/share/*`) on tune bypasses forward
auth entirely; native clients authenticate with Subsonic's own user/
password, which is the Navidrome-local user that the proxy auth
initially provisioned.

## LDAP (no OIDC client)

Jellyfin's native clients (Apple TV / Infuse) bind LDAPS against the
glauth-kratos bridge co-located in the Jellyfin pod. The bridge maps
`metadata_admin.groups` to LDAP `memberOf` entries; the Jellyfin LDAP
plugin reads memberOf to assign Jellyfin policies. Same identity surface
as the cinema OIDC client; the group strings emitted as memberOf match
`jellyfin-admin` / `jellyfin-user` for symmetry across the two paths.

## Rough ranking by role granularity

Most granular to least:

1. **vault (oCIS)** — four roles (admin, spaceadmin, user, guest) plus
   group-level space provisioning.
2. **observe (Grafana)** — four roles (GrafanaAdmin, Admin, Editor,
   Viewer); allow_assign_grafana_admin gates instance admin.
3. **forge (GitLab)** — admin / user / external, plus required_groups
   gating, plus per-project roles set inside GitLab.
4. **listen (Audiobookshelf)** — admin / user / guest hardcoded.
5. **memory (Immich)** — admin / user only.
6. **larder (Mealie)** — admin / user only.
7. **cinema (Jellyfin)** — admin / user only.
8. **keep (Vaultwarden)** — admin / user planned, role mapping not yet
   in mainline.
9. **library (BookLore)** — admin local-only; OIDC does not drive role.
10. **tailscale** — no role mapping; identity only.
11. **llm (vLLM)** — no role concept; bearer-token gate.

## What the IDP can and cannot do

The IDP's contract ends at the id_token. Per-resource ACLs (which
album, which library, which project, which space, which Vaultwarden
collection) live inside each app and stay there. The IDP role drives:

- Whether the user can sign in at all (required_groups, OIDC_USER_GROUP).
- Whether the user is an instance/server admin (admin_groups,
  OIDC_ADMIN_GROUP, GrafanaAdmin, etc.).
- Whether the user gets a coarse JIT-provisioned role tier.

It does not drive which folders, which libraries, or which collections
the user can see. That stays inside the app.

## Audience verification status (A3)

Every `hydra/clients/*.yaml` sets `audience: [https://<app>.dunn.dev]`.
The consent service verifies on lint that `audience-host` overlaps
`redirect-host` (good). It cannot verify that each downstream app
actually checks `aud` on the id_token. If any of the apps below is
misconfigured to skip aud verification (or doesn't expose the option),
a tier-2-compromised app can replay one id_token at another app whose
aud verification is also lax.

Phase 4 lab work populates the "verified in lab" column. Until then,
every row is `NEEDS-VERIFY`.

| App      | client_id  | audience                               | Verified in Phase 4 lab |
|----------|------------|----------------------------------------|-------------------------|
| keep     | keep       | https://keep.dunn.dev                  | NEEDS-VERIFY            |
| larder   | larder     | https://larder.dunn.dev                | NEEDS-VERIFY            |
| listen   | listen     | https://listen.dunn.dev                | NEEDS-VERIFY            |
| cinema   | cinema     | https://cinema.dunn.dev                | NEEDS-VERIFY            |
| memory   | memory     | https://memory.dunn.dev                | NEEDS-VERIFY            |
| vault    | vault      | https://vault.dunn.dev                 | NEEDS-VERIFY            |
| library  | library    | https://library.dunn.dev               | NEEDS-VERIFY            |
| forge    | forge      | https://forge.dunn.dev                 | NEEDS-VERIFY            |
| observe  | observe    | https://observe.dunn.dev               | NEEDS-VERIFY            |
| tailscale| tailscale  | https://login.tailscale.com (LOW-4)    | N/A (RP check by client_id, not aud) |
| llm      | llm        | (client_credentials; no id_token)      | N/A                     |

Per-app verification recipe:

1. Trigger an OIDC sign-in to app X.
2. Capture the id_token issued by Hydra (browser dev tools → network →
   /oauth2/token response).
3. Tamper with `aud`: edit the JWT payload to set `aud` to a different
   app's host, re-sign with the actual Hydra signing key (or just flip
   one byte — the goal is "does the app reject?").
4. Replay the tampered token at app X's session endpoint. App X must
   reject. If it accepts: open an issue in `auth/` with the app name
   and the misbehaving config knob.

Apps that pass receive a green tick in the column; apps that fail
yield a follow-up task to fix the app config. Apps where no
config option exists (e.g., a hypothetical Vaultwarden mainline that
doesn't verify aud) get a Compensating Control note pointing at the
sub-domain isolation that limits replay risk in our shape.
