Statuspage is a generic stand-in for an external, hosted service that the
portal surfaces as a tile but does not authenticate. `auth_kind: external`
means the link points off-instance — a public status page, a vendor console, a
SaaS dashboard — where sign-in (if any) is handled entirely by the third party.

It exists in the catalog purely as a convenience launch point. There is no
OAuth client and no LDAP bind. The tile does require the `access-statuspage`
group, because the portal's tile filter gates all tiles on group membership
regardless of `auth_kind`. The tile is a labeled outbound link to an
external service; it rounds out the example set by showing that not every
entry in the portal is something the identity provider secures.

> **Design note:** the current tile filter in `portal/src/pages/index.astro`
> applies the same group-membership gate to every tile, including `auth_kind:
> external` ones. If you want a tile visible to every authenticated user
> without a dedicated group, the filter would need to special-case external
> tiles. See the open question flagged in the OSS release notes.
