Jellyfin is the free-software media server — movies, TV, and music streamed to
browsers and native client apps, with per-user profiles and libraries.

This fixture authenticates via **LDAP** rather than OIDC. An LDAP bridge sits
in front of the identity store and translates directory binds and group
memberships (`memberOf`) into Jellyfin's own user policies. Native clients
(set-top boxes, mobile apps) often cannot drive a browser-based OAuth redirect,
so an LDAP bind — username and password against the directory — is the
practical path; the bridge maps the resulting group membership onto Jellyfin
roles. Because there is no OAuth client involved, this manifest carries only a
presentation tile and no `oidc:` block; the SSO portal lists it but registers
no Hydra client for it.
