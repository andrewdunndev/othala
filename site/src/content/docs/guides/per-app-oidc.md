# Per-app OIDC

How an application gets connected over OIDC, and the one modelling decision
everything else depends on. The per-app quirks are the expensive part, so the
worked examples here are checked-in manifests that CI exercises rather than
prose that can rot. Not every application speaks OIDC: two other paths exist — a
reverse-proxy `forward_auth` call into the portal's session gate, and a
service-local password for native clients that cannot run a browser redirect.

## The shape

One issuer, fixed once any relying party is wired, and authorization code for
every interactive application — see [Golden path](golden-path.md). One manifest
per application, read at runtime from `MANIFEST_DIR`, so adding one is a
manifest drop rather than an image rebuild. A manifest carries up to three
namespaces: `presentation:` (tile metadata and the access binding), `oidc:`
(forwarded to Hydra), and `consent:` (role and claim shape, read by the portal
and never sent to Hydra).

## Entry and role are different bindings

This is the part worth getting right. Two groups exist per service and they do
different jobs. `<svc>-access` is **entry**: hold it and you get in, and that is
true of everyone, admins included. `<svc>-admin` is **role only**: it elevates
someone already admitted and admits nobody on its own. So "can this person get
in?" is answered by looking at exactly one group.

```yaml
presentation:
  access:
    - audiobookshelf-access       # ENTRY. Only the access group, ever.

consent:
  group_role_map:
    audiobookshelf-admin: admin   # ROLE. Both groups appear here.
    audiobookshelf-access: user
```

`presentation.access` is an OR-list evaluated by `enforceAccessGate` in
`portal/src/lib/gate.ts`, over the list parsed by
`portal/src/lib/access-groups.ts`. Putting `<svc>-admin` in it is exactly what
would make an admin group grant entry on its own — the mechanism this model
exists to abolish. An identity holding only `<svc>-admin` is denied before any
claim is composed; that is a misconfigured identity, not a shortcut.
`portal/scripts/gate.test.mjs`, `portal/scripts/gate-property.test.mjs` and
`e2e/playwright/tests/t-access-model.spec.ts` pin it. Group **names** are
convention only: a group's type comes from which manifest key binds it, never
from its spelling — `portal/src/lib/group-registry.ts` records why name-based
inference was retired.

<figure class="diagram">
  <img src="/diagrams/group-binding-decision.svg" alt="Three columns. The identity holds groups in admin-API-only metadata. The manifest binds them twice: presentation.access is the entry binding, consent.group_role_map is the role binding. The code then decides — the access gate admits on the entry binding, and lookupRole resolves a role from the highest-ranked match. Holding only the admin group admits nobody, and a group no manifest binds grants nothing.">
  <figcaption class="diagram-caption">The identity holds · the manifest binds · the code decides</figcaption>
</figure>

## Wiring a new relying party

Generate a client secret, store it, and write the manifest with
`presentation.access` naming only the access group and `consent.group_role_map`
naming both. Then register the client with Hydra:
`portal/src/lib/register-clients.ts` runs as a one-shot on the network that can
reach the admin port, and it creates and updates but **never deletes**, so
retiring a service leaves a ghost registration until an operator removes it by
hand. Everything to that point is verifiable without the application running.

The secret must land as the same plaintext on both sides — nothing links them,
and a mismatch surfaces as `invalid_client` at the token exchange, which reads
like a provider error. Last, grant the access group: membership is checked
before any token is issued and is admin-API-only, so nothing appears on first
login and there is no self-service path to it. An admin who will also administer
the application gets `<svc>-admin` **as well**, not instead.

## Two worked examples

Both live in `e2e/manifests/`, exercised by CI, so neither can drift silently.

**`audiobookshelf.yaml` — the minimal well-behaved relying party.** A `groups`
claim and a two-entry `group_role_map`; no JMESPath, no nested claim shapes. Its
`presentation.access` comment states why the admin group is absent. Start here.

**`grafana.yaml` — role mapping under an application-specific claim contract.**
A JMESPath role attribute and three declared roles, one reachable only by
per-client override. Its `consent.roles` comment explains why declaration order
is descending privilege: `lookupRole` in `portal/src/lib/claims.ts` reads a
role's index as its rank and keeps the highest rank matched across the whole
group set, which makes resolution independent of storage order. Grafana also
shows the class of quirk that costs time: its role expression is evaluated
application-side, and a separate flag must be enabled or the server-admin role
silently resolves to org-admin only. The general lesson is to read an
application's OIDC documentation for **when** it reads the role, not just where
— several read it at account creation and never re-sync.

## When it is not OIDC

**Forward-auth.** Applications with no usable OIDC client sit behind a reverse
proxy calling `portal/src/pages/api/forward-auth.ts` with a required group as a
query parameter: `200` proxies the request through, `401` is the one status
safe to redirect to login, and `403`/`503` both deny but must never be matched
into that redirect — a `503` means Kratos never answered, not that the user was
refused. `ARCHITECTURE.md` § The forward-auth request path has the full status
contract; `portal/scripts/forward-auth.test.mjs` pins it.

<figure class="diagram">
  <img src="/diagrams/forward-auth-request-path.svg" alt="A browser carrying the apex-scoped session cookie reaches the edge, which routes at L4 by SNI without decrypting, then the service's own proxy — the door, where forward_auth runs before any reverse_proxy. The proxy issues a sub-request to the portal's forward-auth endpoint with the required group as a query parameter set by the edge config, never an inbound header. The portal verifies the session cookie, re-resolves the identity through the Kratos admin API because group metadata is absent from whoami, and applies enforceGroupGate — identity active, every stored group canonical, and in the named group — failing closed at every step. It answers one of four statuses: 200 proxy through with the identity header set from the server-verified session; 401 no usable session, the one status an edge can safely turn into a login redirect; 403 refused on the merits; and 503 when Kratos did not answer, which denies like a 403 but must never be matched into a redirect. The application sees only the identity header.">
  <figcaption class="diagram-caption">One sub-request decides the request, before the app ever sees it</figcaption>
</figure>

**Service-local passwords.** Some native clients cannot run the OAuth browser
redirect at all, so they use a credential in the application's own user
database, set by an admin there; it is not the Kratos password and the two are
never shared. This is the supported pattern for those clients, not a fallback
waiting to be simplified away. An LDAP bridge for the same problem exists as
an unmaintained reference at `gitlab.com/dunn.dev/kratos-ldap`.

## Troubleshooting

Generic OAuth failures mean what they mean anywhere, and Hydra's log says which.
Two are specific to this model:

- **Denied and you are sure they should not be** — check the entry group, not
  the admin group. Entry comes from `<svc>-access` and nothing else.
- **The role is wrong but login works** — that is `group_role_map` and claim
  shape, not the gate. Check what the application reads, and how often.

`ARCHITECTURE.md` holds the issuer URL, cookie domain and subject types as
load-bearing, non-changeable decisions; `DEPLOY.md` holds the promotion path.
