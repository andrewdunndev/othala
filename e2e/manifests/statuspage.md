Statuspage is a generic stand-in for an external, hosted service that the
portal surfaces as a tile but does not authenticate. `auth_kind: external`
means the link points off-instance — a public status page, a vendor console, a
SaaS dashboard — where sign-in (if any) is handled entirely by the third party.

It exists in the catalog purely as a convenience launch point. There is no
OAuth client, no LDAP bind, and no access-group gate on the SSO side; the tile
is a labeled outbound link. It rounds out the example set by showing that not
every entry in the portal is something the identity provider secures.
