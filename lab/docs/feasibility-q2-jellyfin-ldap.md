# Q2: Jellyfin LDAP plugin compatibility for the bridge

## Verdict

**GREEN.** The Jellyfin LDAP plugin's expectations are narrow, well-defined, and
documented in source. A bridge that exposes Kratos identities as LDAP entries
needs to support: simple BIND with a service-account DN, simple BIND with a
user DN found via SEARCH, sub-tree SEARCH with a configurable filter, and
attribute reads on a small handful of attributes (`uid`, `cn`, optionally
`mail`, `displayName`, `memberOf`, `userPassword`, a profile-image attribute).
LDAPv3, no extended controls required, no paged results required for a small
homelab directory. The only load-bearing constraint is that the bridge must
return `memberOf` (or equivalent) on user entries so the admin filter can hit
without a separate group-tree search.

The plugin is also the only viable path for Apple TV / Infuse: the OIDC SSO
plugin is web-only, so for native clients the username/password the client
sends to `/Users/AuthenticateByName` has to land somewhere that can verify
it, and that "somewhere" is the LDAP plugin's `Authenticate(username,
password)` path.

## DN format expected

**Default in the plugin shipped config:** `LdapBindUser =
"CN=BindUser,DC=contoso,DC=com"` and the user lookup returns whatever DN
the directory stores on the matched entry (`ldapUser.Dn`), which is then
re-bound with the user-supplied password.

**How the user DN is determined:** the plugin does *not* construct the user
DN by templating. It SEARCHes for the user under `LdapBaseDn` with the
configured filter, takes the first matching entry, and binds with that
entry's `dn` attribute. Source: `LDAP-Auth/LDAPAuthenticationProviderPlugin.cs`
lines 463-553 (`LocateLdapUser`) and 137-144 (the user-bind block uses
`ldapUser.Dn`).

**Configurable:** anything the bridge wants. Common shapes the plugin's
own placeholder text suggests:

- `cn=username,ou=users,dc=example,dc=com` (the plugin's default)
- `uid=username,ou=people,dc=example,dc=com` (lldap convention)
- `cn=user,ou=users,dc=authentik,dc=domain,dc=com` (Authentik LDAP outpost
  convention)

The bridge can pick any DN convention it likes, so long as the search
returns an entry whose `dn` is bindable. AD-style `username@domain` UPN
binds are *not* used — the plugin always passes a full DN to `Bind()`.

## Search attributes

**User identifier attributes:** controlled by `LdapSearchAttributes` (default
`"uid, cn, mail, displayName"`) and `LdapUidAttribute` (default `"uid"`)
and `LdapUsernameAttribute` (default `"cn"`).

The runtime search filter (when `{username}` is *not* in the search filter)
is built as:

```
(&<configured-search-filter>(|(uid=USER)(cn=USER)(mail=USER)(displayName=USER)))
```

Source: `LDAPAuthenticationProviderPlugin.cs` lines 487-503. The filter is
sub-tree (`LdapConnection.ScopeSub`) under `LdapBaseDn`. If the operator
uses `{username}` in the filter, that branch is taken instead and
`LdapSearchAttributes` is ignored.

The plugin requests only `[UsernameAttr, UidAttr]` (plus the profile-image
attribute when sync is on) on the user search — so the bridge does *not*
need to expose every attribute on the entry, just the configured username
attribute, the configured uid attribute, and (optionally) a profile-image
attribute. Source: lines 514-527.

**Admin determination:** controlled by `LdapAdminFilter` (default
`"(enabledService=JellyfinAdministrator)"`, but realistic deployments use
`(memberOf=cn=jellyfin_admin,ou=groups,...)`).

Two modes:

1. **Default (DN-match) mode.** The plugin runs the admin filter as a
   sub-tree search under `LdapAdminBaseDn` (or `LdapBaseDn` if empty),
   then iterates the result set looking for an entry whose DN equals the
   already-resolved user DN. If found, user is admin. Source: lines 158-189.

2. **memberUid mode** (`EnableLdapAdminFilterMemberUid = true`). The
   plugin runs the filter and admin status is true if *any* entry comes
   back. Used for OpenLDAP `posixGroup` style where the group entry has
   `memberUid: alice` and the admin filter is something like
   `(&(cn=jellyfin-admins)(memberUid={username}))`. Source: lines 173-176.

The admin filter has a `{username}` template substitution applied before
search. The substituted value is OWASP-sanitized (`(`, `)`, `*`, `\`, NUL
are escaped). Source: `Helpers/LdapUtils.cs:SanitizeFilter`.

**Group / memberOf shape:** the plugin does **not** do a separate group
search by default. It expects `memberOf` (or whatever filter the operator
writes) to resolve in a single search against `LdapBaseDn` /
`LdapAdminBaseDn`. Concretely the bridge has two viable shapes:

- **memberOf-on-user (recommended).** Expose `memberOf` as a multi-valued
  attribute on each user entry whose values are group DNs. Operator writes
  search filter `(&(objectClass=person)(memberOf=cn=jellyfin_users,ou=groups,...))`
  and admin filter `(memberOf=cn=jellyfin_admins,ou=groups,...)`.
  Plugin does sub-tree user search, finds the user, runs admin search,
  finds the same user entry, DN matches, user is admin. This is what
  Authentik LDAP outpost and lldap do.

- **posixGroup / memberUid.** Expose group entries with `objectClass:
  posixGroup` and `memberUid: <usernames>`. Operator writes admin filter
  `(&(cn=jellyfin-admins)(memberUid={username}))` and ticks
  "Enable Admin Filter 'memberUid' mode". Plugin doesn't try to DN-match,
  just checks if the search returned any rows.

The Active Directory recursive matching rule
`memberOf:1.2.840.113556.1.4.1941:=...` does not currently work with the
plugin (`LdapException: No Such Object (32)`). The bridge should expose
`memberOf` as a flat, fully-resolved transitive list rather than relying
on the consumer to walk nested groups. (See issue #184.)

## Apple TV / Infuse confirmation

**LDAP plugin is the supported path: yes.** Apple TV (Infuse, Swiftfin)
clients authenticate by POSTing username + password to Jellyfin's
`/Users/AuthenticateByName` HTTP endpoint with the `MediaBrowser`
authorization scheme. Jellyfin server then asks each registered
`IAuthenticationProvider` to authenticate the credentials. The LDAP plugin
implements `IAuthenticationProvider` and runs its full BIND/SEARCH/admin
flow inside that call. The native client sees a normal `AccessToken` /
`User` response and never knows LDAP was involved.

**OIDC plugin alternative:**
- Works for: the Jellyfin Web UI (browser-based redirect flow), and any
  native client that implements Quick Connect (initiate code in browser,
  client polls).
- Fails for: Infuse and most native Apple TV clients. The
  `jellyfin-plugin-sso` README states "This is for Jellyfin >=10.8 and
  only on the Web UI or clients supporting Quick Connect" and "This only
  works on the web UI" before Quick Connect was added. Infuse does not
  expose a Quick Connect flow; it has a username/password form. Without
  LDAP (or native Jellyfin users) those credentials have nowhere to land.

There is one Apple-specific gotcha that is *not* LDAP-related but is worth
flagging: a server build (Jellyfin 2025120105, see jellyfin/jellyfin#15730)
broke Apple-client logins because the auth request validation became
stricter about the `App` and `DeviceId` parameters that Apple clients send.
That was closed as not-a-bug (client-side issue) and is independent of
the auth provider. There is also an older issue (jellyfin/jellyfin#3599)
where Infuse appears to require admin permissions to log in because it
hits an admin-only endpoint right after auth — this is a Jellyfin
permissions concern, not the LDAP plugin.

## Plugin config options

Source: `LDAP-Auth/Config/PluginConfiguration.cs` and `Config/configPage.html`.

| Field | Default | Purpose |
|-------|---------|---------|
| `LdapServer` | `ldap-server.contoso.com` | Hostname / IP of the LDAP server |
| `LdapPort` | `389` | TCP port |
| `UseSsl` | `true` | LDAPS (implicit TLS, typically port 636) |
| `UseStartTls` | `false` | StartTLS upgrade on plain port |
| `SkipSslVerify` | `false` | Disable cert verification (homelab) |
| `LdapClientCertPath` | `""` | Optional client cert (PEM) for mTLS |
| `LdapClientKeyPath` | `""` | Optional client key (PEM) for mTLS |
| `LdapRootCaPath` | `""` | Optional CA bundle (PEM) for server cert verify |
| `LdapBindUser` | `CN=BindUser,DC=contoso,DC=com` | Service-account DN |
| `LdapBindPassword` | `password` | Service-account password |
| `LdapBaseDn` | `o=domains,dc=contoso,dc=com` | Sub-tree root for user searches |
| `LdapSearchFilter` | `(memberOf=CN=JellyfinUsers,DC=contoso,DC=com)` | User filter; supports `{username}` substitution |
| `LdapSearchAttributes` | `uid, cn, mail, displayName` | Attributes to OR-match against the supplied login when filter has no `{username}` |
| `LdapUidAttribute` | `uid` | Stable identifier persisted in the plugin's user-link table |
| `LdapUsernameAttribute` | `cn` | Mapped to Jellyfin's `User.Username` |
| `LdapPasswordAttribute` | `userPassword` | Used only if password change is enabled |
| `AllowPassChange` | `false` | If true, plugin offers to change passwords (uses extended op `1.3.6.1.4.1.4203.1.11.1` if the server advertises it, otherwise direct attribute modify) |
| `LdapAdminBaseDn` | `""` (falls back to `LdapBaseDn`) | Sub-tree root for admin filter search |
| `LdapAdminFilter` | `(enabledService=JellyfinAdministrator)` | Admin filter; supports `{username}` substitution; literal `_disabled_` disables it |
| `EnableLdapAdminFilterMemberUid` | `false` | Switch admin check from DN-match to "any result == admin" |
| `CreateUsersFromLdap` | `true` | Auto-provision Jellyfin user record on first login |
| `EnableLdapProfileImageSync` | `false` | Pull profile images from LDAP |
| `LdapProfileImageAttribute` | `jpegphoto` | Attribute holding the image |
| `LdapProfileImageFormat` | `Default` | One of `Default` (auto-sniff), `Binary`, `Base64`, `Url` |
| `RemoveImagesNotInLdap` | `false` | Delete Jellyfin-side image if absent in LDAP |
| `EnableAllFolders` | `false` | New users get access to every library |
| `EnabledFolders` | `[]` | Specific library IDs new users get access to |
| `PasswordResetUrl` | `""` | Optional URL with `$userId` and `$userName` substitutions |

## Schema mapping for our bridge

**LDAP entry shape we need to expose:**

User entry (objectClass example: `inetOrgPerson` or `person`, plus
whatever is convenient):

```
dn: uid=<kratos-traits.username>,ou=people,dc=auth,dc=dunn,dc=dev
objectClass: inetOrgPerson
uid: <kratos-traits.username>
cn: <kratos-traits.username or display name>
mail: <kratos-traits.email>
displayName: <kratos-traits.name>
memberOf: cn=jellyfin_users,ou=groups,dc=auth,dc=dunn,dc=dev
memberOf: cn=jellyfin_admins,ou=groups,dc=auth,dc=dunn,dc=dev   (admins only)
userPassword: <opaque, only used if password change is enabled>
```

**Required attributes** (anything the plugin reads with default config):

- The `dn` itself (used for the user BIND step).
- `LdapUidAttribute` (default `uid`) — must be stable across renames; the
  plugin keys its internal Jellyfin↔LDAP user table on this. Renaming this
  value mid-flight effectively re-creates the user.
- `LdapUsernameAttribute` (default `cn`) — becomes the Jellyfin username,
  surfaced to clients. Pick the human-readable handle for this.
- Whatever attributes appear in the operator's `LdapSearchAttributes`
  list. The defaults are `uid, cn, mail, displayName`. The bridge should
  expose all four if reasonable so operators can let users log in with
  email or username interchangeably.
- `memberOf` on the user entry, populated transitively (no nested-group
  walking required from the consumer). This is what makes the admin
  filter work in a single search.

**Optional attributes:**

- `userPassword` — only if the bridge intends to surface password-change
  via LDAP modify or RFC 3062 extended op. For a Kratos-backed bridge
  this is almost certainly out of scope; document it as not supported and
  recommend operators leave `AllowPassChange` off.
- `jpegPhoto` (or whatever attribute the operator points
  `LdapProfileImageAttribute` at) — convenient but optional. Kratos
  identities won't usually have these.

**Group entry shape** (needed for `memberOf` DNs to resolve, and for the
`memberUid` mode if the bridge wants to support it):

```
dn: cn=jellyfin_users,ou=groups,dc=auth,dc=dunn,dc=dev
objectClass: groupOfNames
cn: jellyfin_users
member: uid=alice,ou=people,dc=auth,dc=dunn,dc=dev
member: uid=bob,ou=people,dc=auth,dc=dunn,dc=dev

dn: cn=jellyfin_admins,ou=groups,dc=auth,dc=dunn,dc=dev
objectClass: groupOfNames
cn: jellyfin_admins
member: uid=alice,ou=people,dc=auth,dc=dunn,dc=dev
```

The Jellyfin plugin itself will not directly query group entries in the
default DN-match mode — it relies on `memberOf` on the user — but other
clients in the LDAP estate (and Authentik-style outposts that proxy
Jellyfin) will. Expose group entries as first-class even if Jellyfin
alone wouldn't need them.

## Compatibility gotchas

1. **No paged-results support.** The plugin uses
   `Novell.Directory.Ldap.NETStandard` and calls `Search(...)` without a
   paged-results control. If the bridge returns more than the LDAP-server
   `sizeLimit` matches for the search filter, the plugin throws
   `Sizelimit Exceeded (4)` and authentication fails — even if the user's
   own entry would have been in the result set. Issue #39 is the canonical
   reference. Mitigation on the bridge side: do not impose a small
   default size limit, or scope `LdapBaseDn` tightly enough that no
   single search returns thousands of entries. For a homelab with <100
   identities this is a non-issue; document it for future scaling.

2. **No nested-group walking via AD's matching-rule-in-chain OID.** The
   filter `memberOf:1.2.840.113556.1.4.1941:=...` does not work (issue
   #184, Novell library limitation). The bridge must precompute
   transitive group membership and expose it as flat `memberOf` values.

3. **Admin DN-match requires a single base.** The plugin's admin search
   uses one base DN (`LdapAdminBaseDn` or `LdapBaseDn`) and DN-compares
   against the already-resolved user DN. If users live under a different
   sub-tree from where the admin filter is rooted, the admin entries the
   admin search returns won't DN-match, and admin status silently stays
   false. Issue #194 is exactly this case. The bridge should keep all
   user entries under one consistent sub-tree and let `memberOf`
   distinguish admins, rather than putting admins in a separate OU.

4. **Filter sanitization is OWASP-style for the user-supplied portion only.**
   `(`, `)`, `*`, `\`, NUL get hex-escaped before the username is spliced
   into the filter. The static portion of the filter (everything the
   operator types in `LdapSearchFilter`) is passed through verbatim, so a
   malformed filter from the operator is what it is — the plugin doesn't
   validate filter syntax beyond what `Novell.Directory.Ldap` does at
   parse time.

5. **First match wins on user search.** If the search returns multiple
   matches the plugin warns and uses the first. The bridge must guarantee
   uniqueness on whatever attribute combination the search filter
   resolves. With Kratos identities this means the bridge needs a stable
   primary key (Kratos identity ID is the obvious choice, mapped to
   `uid`).

6. **Re-keying breaks the user link.** The plugin stores
   `LinkedJellyfinUserId ↔ ldapUid` in its own configuration. If the
   `LdapUidAttribute` value changes for a given identity, the plugin
   falls back to looking up by `LdapUsernameAttribute` and effectively
   treats the user as new if both have changed. Pick a Kratos field
   that's stable for life — identity ID (a UUID) is best.

7. **Referral following is on by default.** The plugin sets
   `Constraints.ReferralFollowing = true` and provides an
   `LdapAuthHandler` that re-binds with the service-account credentials
   on every referral. If the bridge issues referrals (it almost
   certainly shouldn't), they'll be chased. Safest is to issue zero
   referrals.

8. **TLS is the operator's problem.** With `UseSsl = true` and no CA
   path, the plugin uses the OS trust store. With `LdapRootCaPath` set,
   it custom-verifies against the supplied PEM bundle. With
   `SkipSslVerify = true`, it returns `true` from the verification
   callback unconditionally. The bridge should support both LDAPS (port
   636 conventionally) and StartTLS on 389; both work in the plugin and
   are toggled independently. mTLS via client cert is also supported
   (`LdapClientCertPath` + `LdapClientKeyPath`, PEM only).

9. **No SASL.** The plugin only does simple bind. If the bridge plans
   to support SASL EXTERNAL or GSSAPI for non-Jellyfin consumers, that's
   fine — but Jellyfin will use simple bind regardless.

10. **Password-change extended op.** If `AllowPassChange = true`, the
    plugin first checks the RootDSE for support of OID
    `1.3.6.1.4.1.4203.1.11.1` (RFC 3062 Password Modify). If present, it
    uses that. If not, it does an `LdapModification.Replace` on
    `LdapPasswordAttribute`. For a Kratos-backed bridge, recommend
    leaving password change off and routing recovery through Kratos's
    own flows; advertising the extended op without backing it would
    surface confusing failures.

11. **Plugin requires LDAPv3.** The Novell library defaults to v3 and
    the plugin doesn't override; v2-only directories won't work, but no
    serious LDAP server has been v2-only for two decades. Not a
    practical concern.

## Existing reference configs

- **Authentik LDAP outpost + Jellyfin** — Authentik's official integration
  page at <https://integrations.goauthentik.io/media/jellyfin/>. Recommended
  values: bind `cn=ldap_bind_user,ou=users,dc=company,dc=com`, base
  `dc=company,dc=com`, port 636, search filter
  `(&(objectClass=user)(memberOf=cn=jellyfin_users,ou=groups,dc=company,dc=com))`,
  attributes `uid, cn, mail, displayName`, name attribute `cn`, password
  attribute `userPassword`. Authentik LDAP outposts run on 3389 (StartTLS)
  / 6636 (LDAPS) by default in their containerized deployments. Cross-ref:
  jellyfin/jellyfin-plugin-ldapauth#120 (community guide), and the
  ad3m3r5 gist <https://gist.github.com/ad3m3r5/8e71da9c6ce317dd78f043f7eab1d4a6>.

- **lldap + Jellyfin** — official lldap example at
  <https://github.com/lldap/lldap/blob/main/example_configs/jellyfin.md>.
  Bind `uid=jellyfin_bind_user,ou=people,dc=example,dc=com`, base
  `ou=people,dc=example,dc=com`, search filter
  `(memberof=cn=media,ou=groups,dc=example,dc=com)`, admin filter
  `(memberof=cn=media_admin,ou=groups,dc=example,dc=com)`, attributes
  `uid, mail`, uid `uid`, username `uid`, password `userPassword`.
  Password change requires the bind user to have `lldap_password_manager`.

- **kanidm + Jellyfin** — kanidm's LDAP server has unusual DN shapes
  (entries are direct subordinates of `domain_info`, e.g.
  `spn=alice@idm.example.com,dc=idm,dc=example,dc=com`) and limited
  attribute remapping. There is no official Jellyfin recipe in kanidm's
  docs (<https://kanidm.github.io/kanidm/stable/integrations/ldap.html>).
  Community practice is to put kanidm's `ldap-proxy`
  (<https://github.com/kanidm/ldap-proxy>) in front to flatten DN shapes
  before Jellyfin sees them. Worth knowing as a cautionary tale: directories
  whose DN shape doesn't match Jellyfin's "search-then-bind-the-DN"
  expectation force consumers to add a translation layer. Our bridge
  should not be one of those — keep DN shapes conventional.

- **OpenLDAP / Symas** — Symas KB at
  <https://kb.symas.com/en_US/reference/using-openldap-with-jellyfin>.
  Bind `cn=admin,dc=example,dc=com`, search filter
  `(&(objectClass=person)(uid={username}))`, demonstrates the
  `{username}` template substitution path.

## Sources

Primary (plugin source, latest released v22, Nov 2025):

- `jellyfin/jellyfin-plugin-ldapauth` repo, master branch:
  <https://github.com/jellyfin/jellyfin-plugin-ldapauth>
- `LDAP-Auth/Config/PluginConfiguration.cs` — full config surface and
  defaults, lines 1-247.
- `LDAP-Auth/LDAPAuthenticationProviderPlugin.cs` — the
  `Authenticate(username, password)` flow (lines 89-285), `LocateLdapUser`
  search shape (lines 463-553), bind helper (lines 639-673), referral
  handler wiring (lines 630-637), admin search and DN-match (lines
  146-196).
- `LDAP-Auth/Helpers/LdapUtils.cs` — OWASP-style filter sanitization
  (lines 22-52).
- `LDAP-Auth/LdapAuthHandler.cs` — automatic referral re-bind handler.
- `LDAP-Auth/Config/configPage.html` — operator-facing copy that
  documents the two filter modes (`{username}` template vs.
  search-attribute OR-list), and the admin filter / memberUid mode toggle.
- `LDAP-Auth/Api/LdapController.cs` — `TestServerBind`, `TestLdapFilters`,
  `TestSearchFilter` admin-only test endpoints.

Plugin issues:

- jellyfin/jellyfin-plugin-ldapauth#39 — sizelimit-exceeded on >1000
  users, no paged-results support.
- jellyfin/jellyfin-plugin-ldapauth#120 — community Authentik LDAP outpost
  guide.
- jellyfin/jellyfin-plugin-ldapauth#184 — AD recursive matching rule
  `1.2.840.113556.1.4.1941` not working.
- jellyfin/jellyfin-plugin-ldapauth#194 — admin filter under a separate
  base DN breaks DN-match.

Jellyfin server / API:

- `jellyfin/jellyfin#15730` — Apple-client login regression in
  2025120105, closed as client-side, unrelated to LDAP.
- `jellyfin/jellyfin#3599` — Infuse requires admin endpoint after login,
  unrelated to LDAP.
- Kotlin SDK auth docs — `/Users/AuthenticateByName` is the
  username/password path that LDAP plugin services:
  <https://kotlin-sdk.jellyfin.org/guide/authentication.html>.

OIDC / SSO plugin (for the negative half of the Apple TV question):

- `9p4/jellyfin-plugin-sso` README — explicit "only works on web UI or
  clients supporting Quick Connect" caveat:
  <https://github.com/9p4/jellyfin-plugin-sso>.

LDAP library:

- `dsbenghe/Novell.Directory.Ldap.NETStandard` — the underlying LDAP
  client. LDAPv3, simple bind, supports paged-results control via a
  separate add-on (`metacube/PagedResultsControl`) that the plugin does
  not pull in.

Reference deployments:

- Authentik LDAP outpost: <https://integrations.goauthentik.io/media/jellyfin/>.
- lldap: <https://github.com/lldap/lldap/blob/main/example_configs/jellyfin.md>.
- kanidm: <https://kanidm.github.io/kanidm/stable/integrations/ldap.html>
  and <https://github.com/kanidm/ldap-proxy>.
- OpenLDAP / Symas: <https://kb.symas.com/en_US/reference/using-openldap-with-jellyfin>.
- Community Authentik gist: <https://gist.github.com/ad3m3r5/8e71da9c6ce317dd78f043f7eab1d4a6>.
- jellytin reference: <https://github.com/sam-6174/jellytin/blob/master/docs/jellyfin_ldap.md>.
