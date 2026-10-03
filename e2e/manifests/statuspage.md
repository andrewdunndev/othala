Statuspage stands in for an external hosted service the portal links to but
does not authenticate (`auth_kind: external`). It has no OAuth client and no
credential.

It shows the default-group fallback: `statuspage.yaml` has no `access` list,
so the tile gates on the default group, `everyone`. Every tile gates on group
membership, whatever its `auth_kind`. An admin assigns `everyone` to the people
who should see broadly visible tiles and sets an `access` list on tiles that
need tighter control.
