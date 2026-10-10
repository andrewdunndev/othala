# Decisions

Reasoning you cannot recover from the code: roads not taken and invisible constraints. Each entry
names the file that fails when it is violated, or says UNENFORCED.

## Assurance level is per-flow, so the session check stays aal1

**Decided.** `session.whoami.required_aal` stays `aal1`. Step-up lives in the application instead:
the admin UI guard, `required_aal: highest_available` on the settings flow, and app sign-in and
forward-auth for accounts holding totp, webauthn, the admin marker or a role above an app's entry
role (`portal/src/lib/gate.ts`).
Admins cannot sign in by emailed code or hold the marker without a second factor. Admins and people with
a role above an app's entry level cannot remove their last one.

**Why.** Kratos enforces assurance level per flow, never per route, so step-up belongs in the
application, which reads the session's AAL itself. Raising the pin tightens nothing: the session endpoint
stops returning a usable identity for exactly the people who enrolled a second factor, and that identity
id is the gate's only input, so every gated app locks out at once. Ory config is mounted by the consumer, so a stale
setting's consumer may be outside this repository.

**Enforced by.** `portal/scripts/forward-auth.test.mjs` holds the coupling (a session with no identity
id is 401). Step-up: `gate.test.ts`, `oauth2-handlers.test.mjs`, `admin-port.test.mjs`,
`admin-actions.test.ts`, `second-factor-gate.test.ts`, `e2e/playwright/tests/v-app-stepup.spec.ts`. The pinned value in
`kratos/kratos.yml` is UNENFORCED.

## An outage is not a denial

**Decided.** The forward-auth endpoint answers 200 / 401 / 403 / 503, with 503 reserved for "could not
establish the facts". Every non-200 denies; the statuses tell the edge which kind of failure occurred.

**Why.** Folded into 403, an outage would send an edge matching `401 403` into an infinite login loop: the
gate denies because it cannot reach the IdP, and the edge redirects to a login page served by the process that is down.
`ARCHITECTURE.md`'s status contract carries the full argument. The required group arrives as an
operator-set query parameter, not a header, because anything reaching the endpoint internally can forge
a header. HEAD reuses the GET decision, since a divergent HEAD would admit what GET refuses.

**Enforced by.** `portal/scripts/forward-auth.test.mjs`

## Admin authority is a boolean the identity service never validates

**Decided.** Admin authority is a strict boolean at `metadata_admin.admin`, granted and revoked live
through the admin UI, over an always-available bootstrap floor: identities seeded out of band that reach
the system only through the network-isolated admin API.

**Why.** Kratos treats `metadata_admin` as opaque; three empirical facts follow. Kratos mints identity
ids and rejects caller-supplied ones on create, so an env allowlist of admin UUIDs could only be filled
by create, read back the minted id, write config, restart: changing the admin set becomes a redeploy.
Kratos validates the identity schema against `traits` only, so the schema's `metadata_admin` block never
executes: it is documentation, the application's validator is the sole runtime enforcement, and a
deployed schema can fail to enumerate the very key the application reads as authority. Kratos also omits
`metadata_admin` from the identity passed to after-hook body templates, so a hook needing to know
whether an identity is an admin must call the admin API, not read its own context.
Admin authority is not a group: groups are user-visible data carried in OIDC claims, and an admin bit
there would let an unprivileged session probe its own admin status. The floor lets the live mechanism
carry hard guards (no demoting the last admin, no self-revoke) without becoming a lockout, since an
identity provider's break-glass cannot route through itself. Self-service recovery refuses admin
identities for the same reason.

**Enforced by.** `portal/src/lib/metadata-admin.ts` (strict-boolean, allowed-key validation),
`portal/src/lib/identity-facts.ts`, `portal/src/lib/admin.ts` (AAL2 guard),
`portal/src/pages/admin/users/[id].astro` (last-admin, self-revoke), `portal/src/server/listen.ts`
(recovery refused on an admin marker the gate fetches itself). `kratos/hooks/recovery-gate.jsonnet`
carries only the identity id and the admin marker is read from the admin API.

## Nothing is derived — not entry from a role, not a type from a name

**Decided.** Entry to an app comes from holding a group the app's manifest binds for access — always,
for everyone, admins included. An elevated role comes from additionally holding a role-mapped group. A
group's type comes from its bindings, never from its name.

**Why.** Deriving entry from a role (a capability group conferring access as a side effect, or the admin group
implicitly granting it) leaves a service's access list without the whole answer. A rule that must be
remembered will be misremembered, so the model requires reconstructibility from one artifact; the price
is two group assignments per admin per service. Because an admin then holds two role-mapped groups and
normalization sorts alphabetically, a first-match walk would hand every admin the low role, so the
resolver takes the highest-ranked declared role over the whole set. A naming prefix cannot be both
convention and runtime type discriminator. Binding and role mapping stay separate fields for the case
where everyone in a group may enter while only a second earns the editor role.

**Enforced by.** `portal/src/lib/gate.ts`, `portal/src/lib/claims.ts` (highest-rank resolution),
`portal/src/lib/group-registry.ts` (binding-derived typing), `portal/scripts/gate-property.test.mjs`,
`e2e/playwright/tests/t-access-model.spec.ts`

## The durable identity key cannot be the migration key

**Decided.** The identity UUID (`sub`) is the durable key every relying party links on and must end on.
The username is only the first-link key, set per app before OIDC is enabled, and only an administrator
can change it. Email is never a link key.

**Why.** The UUID is minted at identity creation, so it exists nowhere in pre-existing application data; the
only key in both is the human one. Relying parties match once by username, persist the UUID, and match
on it after. Email is rejected because it is mutable. A rebuild that recreates identities breaks every
link: import identities with their ids, or budget a re-link pass. Kratos cannot freeze a trait, and an
app that re-matches on username at every sign-in would orphan the account on a self-service rename, so
the profile flow refuses one before it is saved.

**Enforced by.** `handleProfileGate` in `portal/src/server/listen.ts` on
`selfservice.flows.settings.after.profile` in `kratos/kratos.yml`; `portal/scripts/admin-port.test.mjs`,
`e2e/playwright/tests/y-username-admin-only.spec.ts`. Which key each app links on is relying-party
configuration, unenforced here.

## The passkey is the primary credential, not a second factor

**Decided.** Passkey is the primary credential everywhere. Email one-time-code is a full login method
ranked above password. Username plus password is the tertiary recovery on-ramp and the credential the
break-glass floor identities carry.

**Why.** Kratos's passkey strategy gives discoverable credentials and conditional UI (usernameless one-tap);
its webauthn strategy serves only as a hardware second factor with passwordless disabled, so it never
duplicates the primary. Email one-time-code sits above password so a user on a new or borrowed device
gets in without typing a rarely used secret, landing straight in passkey enrollment. Password stays
enabled because the break-glass floor must work when passkey enrollment and email delivery are both degraded.

**Enforced by.** `e2e/playwright/tests/k-email-code-login.spec.ts` end to end. The passkey leg
(`i-passkey-register-login.spec.ts` I1) covers registration and usernameless login. UNENFORCED, like the tier
ORDER and the webauthn strategy's disabled passwordless — `kratos/kratos.yml` holds those values and
nothing fails when they change.

## No password ever transits a channel

**Decided.** There is no self-service registration. An admin creates the identity with no credentials
block, mints a one-time recovery link and code in the same request, and hands both over on a
conversation that already exists with that person. The recipient establishes their own password and
passkey in their own browser.

**Why.** The invariant is that no password ever transits a channel. A code emailed at creation is a delivery
guess: the address is an unverified trait the admin just typed. An admin-chosen initial password is
refused outright. Both link and code are required: the link alone lands on a form with an empty code
field and dead-ends every invitee. The admin-minted code expires slowly because an enrollment message
may sit unread overnight; self-service recovery expires fast.

**Enforced by.** `portal/src/lib/admin-api.ts` (identity created with no credentials block; link and
code minted together). The both-values rendering at the admin call sites is UNENFORCED.

## TLS is a network boundary, not an application concern

**Decided.** Applications speak plain HTTP and never load a certificate; where a real boundary exists, a
sidecar holds the cert. A hop between mutually trusted services on one private network gets network
isolation instead of mTLS or transport encryption. Issuer choice follows one question — must a browser
or device trust this out of the box — and the two roots are never cross-signed.

**Why.** In-app TLS would make every app own cert loading, renewal and error handling. An mTLS proxy in front
of the admin API is rejected the same way: mTLS earns its keep across a trust boundary, and there is
none between two containers on one isolated bridge. Database connections run unencrypted for the same
reason. The cost is real: "is on this network" is weaker than "presents a rostered client certificate".
Chaining an internal root under a public one fails on feasibility (a public CA will not sign
intermediates for non-public use) and blast radius. None of this transfers once the database stops
sharing a private network with its clients.

**Enforced by.** UNENFORCED here — no file in this repository declares the deployment's networks or port
publications, so nothing fails when the isolation the argument rests on regresses.

## Consent is skipped per client, never as a server default

**Decided.** Trusted first-party clients are registered with consent skipped, declared per client in
that client's manifest rather than as a server-wide default.

**Why.** "Which apps skip consent?" stays answerable by grepping manifests, and a server default would grant
the skip silently to whatever is registered next. Accepted threat: consent is the one place a victim
might notice an app they did not open, so a stolen session mints tokens across every first-party
surface silently and the session cookie becomes the entire perimeter. The first money-moving,
irreversible or destructive client warrants per-action re-consent or step-up regardless.

**Enforced by.** `portal/src/lib/oauth2-handlers.ts` (the consent handler honours the per-manifest flag;
a client without it bounces to the interactive screen)

## Proxy route order, and who actually needs a CORS entry

**Decided.** The portal owns the authorization server's login, consent and logout challenge routes, and
the fronting proxy must match that exact path set before any wider wildcard routing to the authorization
server. The CORS allowlist is keyed by client type: a browser SPA that fetches discovery and token
endpoints needs an entry; a redirect-flow server-side client never does.

**Why.** Inverting the proxy route order breaks every login outright: the challenge paths get proxied to the
authorization server, which does not implement them. A redirect-flow client's browser never makes a
cross-origin request to it, so its origin adds nothing, and since credentials are allowed each extra
origin widens who can reach the token endpoint.

**Enforced by.** UNENFORCED — the constraint holds only in the deployed proxy config, which no gate here
can read.

## PKCE enforcement is all-or-nothing, so it is a deliberate hold

**Decided.** Global PKCE enforcement stays off, with enforcement for public clients on as a forward
guard — held deliberately rather than flipped.

**Why.** The authorization server has no per-client PKCE knob, so the choice is global. "No client needs the
relaxation" is not "every client sends a challenge": a confidential client that omits it breaks the
moment enforcement goes on, discovered at login time by its users rather than at deploy time by a gate.
Retired when a non-PKCE relying party ships (keep it off), its rollout is abandoned (verify every
confidential client, then enforce), or the server ships a per-client knob.

**Enforced by.** `hydra/hydra.yml` holds the value, but UNENFORCED — nothing verifies that deployed
clients send a challenge, which is exactly the gap that makes flipping it dangerous.

## The login UI cannot run at a serverless edge

**Decided.** The login, consent and challenge UI runs inside the same private network as the identity
and authorization services, not on an edge or serverless runtime.

**Why.** The Ory admin APIs have no authentication of their own; network position is the authorization, and no
edge function can reach a private network. Reading identity metadata, registering clients and resolving
group membership all need the admin API, so even "is this person allowed in" needs the privileged hop.

**Enforced by.** UNENFORCED — nothing prevents re-adopting an edge adapter; the failure would surface as
unreachable admin endpoints at runtime.

## Edge authorization is walked down a ladder, not argued per service

**Decided.** Which authorization a service surface gets is derived by walking a fixed ladder — use OIDC
where the app supports it natively; do not break native clients; gate sensitive browser-only surfaces
behind forward-auth — rather than decided on each service's own merits.

**Why.** Without a stated rule each service got its own defensible answer; the ladder is reproducible by
someone who was not in the room. The non-obvious rung is the second: a native client carries a bearer
credential rather than the browser's session cookie, so a uniform edge gate rejects it, and the
carve-out is scoped to that client's paths. That rung also rules out a privileged bridge listener
between browser and native auth. The endpoint reads a single group per call, so "entry AND role" is two
gates on one site. An ungated surface is an assignment a rung made, not an omission.

**Enforced by.** UNENFORCED. The single-value group read is visible in
`portal/src/pages/api/forward-auth.ts`, but nothing fails if a second parameter is added, and the
agreement between a declared binding and what a service's edge config gates is unobservable here.
