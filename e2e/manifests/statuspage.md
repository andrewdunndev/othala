Statuspage is a generic stand-in for an external, hosted service that the
portal surfaces as a tile but does not authenticate. `auth_kind: external`
means the link points off-instance — a public status page, a vendor console, a
SaaS dashboard — where sign-in (if any) is handled entirely by the third party.

It exists in the catalog purely as a convenience launch point. There is no
OAuth client and no LDAP bind. The portal's tile filter gates all tiles on
group membership regardless of `auth_kind`, so this tile (like every other)
requires the user to be in an appropriate group.

This fixture demonstrates the **default-group fallback**: `access_group` is
intentionally omitted from `statuspage.yaml`. When `access_group` is absent,
the tile gates on `OTHALA_DEFAULT_GROUP` (default value `everyone`). An admin
assigns the default group to users who should see such broadly-visible tiles;
no user is placed in it automatically.

> **Design note:** every tile in Othala gates on group membership — there is no
> ungated path, even for `auth_kind: external` tiles. Use the default group
> (`everyone` by default, operator-configurable via `OTHALA_DEFAULT_GROUP`) for
> tiles you want visible to most authenticated users, and set an explicit
> `access_group` for tiles that need tighter control.
