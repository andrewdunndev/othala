# Golden path

Most upgrade pain in an Ory deployment comes from surfaces you chose to depend
on. This lists what this project deliberately does not touch and what re-opening
each would cost. Three areas move between Ory releases: the self-service flow UI
contract (node groups, error field placement, conditional UI flags), admin API
response shapes, and newly added grant types. Every commitment below is a
decision not to read one of them.

## 1. Registration is admin-driven, not self-service

`kratos/kratos.yml` disables the self-service registration flow; onboarding is
an operator issuing a one-time enrolment link plus a separate code, out of
band. That avoids the most frequently changed area of Kratos and is the cheapest
anti-abuse control: no unauthenticated caller can create an identity. **Cost of opening it:** track registration-flow node-group
changes on every bump, and build the abuse resistance self-service implies.

That handoff keeps the invariant in DECISIONS.md § No password ever transits a channel:

<figure class="diagram">
  <img src="/diagrams/first-credential.svg" alt="An admin creates the identity through the admin API with no credentials block at all, then mints a one-time recovery link and code together and hands both over on a conversation that already exists with that person; link and code stay apart from any password. The recipient's own browser is where a password and a passkey first get set. One branch refuses outright: when the target carries the admin marker, shouldRefuseRecovery refuses before Kratos is ever asked, console-only.">
  <figcaption class="diagram-caption">Not "no password exists" — no password ever transits a channel</figcaption>
</figure>

## 2. Admin listings cap and render; they never read a total count

`listIdentities` in `portal/src/lib/admin-api.ts` asks for a fixed page size
and renders what comes back, so pagination changes between releases do not
reach the portal. The endpoint paginates via a `Link` header this call does not
follow, so the listing truncates past the cap; revisit first if identity count grows.
**Cost of opening it:** a "page 3 of 47" UI needs a total count, and that header
comes and goes per endpoint and version.

## 3. The portal renders its own auth UI

`portal/src/pages/auth/` renders login, verification, recovery and settings. It
drives Kratos's self-service APIs but renders its own markup, and never
branches on emitted UI state flags or node-group names. **Cost of opening it:**
adopting the reference self-service UI inherits every Kratos UI-shape change,
the largest upgrade burden available in a Kratos integration.

## 4. Conservative grant types and public subject identifiers

Every manifest's `oidc:` block uses authorization code plus refresh token,
client credentials, or the device code grant for a public client — no implicit.
New grant types are additive in Hydra, so an integration requesting none of them
never touches the new surface. Likewise `hydra/hydra.yml` supports only `public`
subject types. **Cost of opening it:** pairwise is fine operationally but
one-way per client.

## 5. The pod network is the trust domain; no in-pod mTLS

Plain HTTP between the portal, Kratos and Hydra, admin APIs included. No peer
address is hard-coded: every host in `kratos/kratos.yml` and `hydra/hydra.yml`
is a `${VAR}` token, so the same file renders for a single-network test harness
and for a segmented deployment. Re-examine this first as a deployment grows;
[Hardening](hardening.md) states its residual risk. **Cost of opening it:** operator time, permanently.

## 6. One admin-marker gate extends Kratos flows

One handler in `portal/src/server/listen.ts` refuses admin identities email
recovery and sign-in by emailed code, so email alone never yields admin
authority. `portal/scripts/admin-port.test.mjs` and spec j cover it. **Cost of
opening it:** every additional webhook is another contract with Kratos's
webhook schema to re-verify on each bump. 

## 7. One secret per rotation slot, no standing second slot

Ory models rotation as distinct entries in a secrets array (the first signs,
older ones still verify), and Kratos and Hydra enforce `uniqueItems` on them, so
a duplicated slot is a config error. Rotation prepends a distinct entry rather
than keeping a standing second slot. Hydra's at-rest system secret cannot rotate:
it is generate-once for the life of the database, and changing it is a rebuild event.

## 8. One writer for identity metadata

Every write to an identity's `metadata_admin` goes through
`validateMetadataAdmin` in `portal/src/lib/metadata-admin.ts`, because Kratos
treats that object as opaque and validates nothing inside it. In-pod, the portal is the only writer. **Cost of opening it:** a second writer — a CLI, a migration
script — must share the validator, or typo'd groups land in storage and
silently remove access.

Revisit when a release breaks one of these or scale genuinely needs a door
opened. Default closed.
