# Decisions

Reasoning you could not recover by reading the code: roads not taken, invisible constraints, and
reversals, so they are not re-litigated. Behaviour lives in the code and the tests. Each entry stands
alone and names the file that fails when it is violated, or says UNENFORCED.

## Assurance level is per-flow, so the session check stays aal1

**Decided.** `session.whoami.required_aal` stays `aal1`. Step-up lives in the application instead:
the admin UI guard, `required_aal: highest_available` on the settings flow, and app sign-in and
forward-auth for accounts holding totp, webauthn or the admin marker (`portal/src/lib/step-up.ts`).
Admins cannot sign in by emailed code, hold the marker without a second factor, or remove the last one.

**Why.** Kratos enforces assurance level per flow, never per route, so step-up belongs in the
application, which reads the session's AAL itself. Raising the pin tightens nothing: the session endpoint
stops returning a usable identity for exactly the people who enrolled a second factor, and that identity
id is the gate's only input, so every gated app locks out at once.

**Enforced by.** `portal/scripts/forward-auth.test.mjs` holds the coupling (a session with no identity
id is 401). Step-up: `step-up.test.ts`, `oauth2-handlers.test.mjs`, `admin-port.test.mjs`,
`admin-actions.test.ts`, `second-factor-gate.test.ts`, `e2e/playwright/tests/v-app-stepup.spec.ts`. The pinned value in
`kratos/kratos.yml` is UNENFORCED.

## An outage is not a denial

**Decided.** The forward-auth endpoint answers 200 / 401 / 403 / 503, with 503 reserved for "could not
establish the facts". Every non-200 denies; the statuses tell the edge which kind of failure occurred.

**Why.** Were 503 folded into 403, an edge matching `401 403` and redirecting would turn an
identity-provider outage into an infinite login loop: the gate denies because it cannot reach the IdP,
and the edge bounces the browser to a login page served by the same process that is down.
`ARCHITECTURE.md`'s status contract ("Why 503 is separate at all") carries the full argument. The required group arrives as an operator-set query
parameter, not a header, because anything reaching the endpoint internally can forge a header; and HEAD
reuses the GET decision verbatim.

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
whether an identity is an admin must call the admin API, not read its own context. Admin authority is not a group: groups are user-visible display data carried in OIDC claims. The floor exists so the live
mechanism can carry hard guards — refusing to demote the last admin, blocking self-revoke — without
becoming a lockout, and because an identity provider's break-glass cannot route through itself.
Self-service recovery refuses admin identities for the same reason.

**Enforced by.** `portal/src/lib/metadata-admin.ts` (strict-boolean, allowed-key validation),
`portal/src/lib/admin-auth.ts`, `portal/src/lib/admin.ts` (AAL2 guard),
`portal/src/pages/admin/users/[id].astro` (last-admin, self-revoke), `portal/src/server/listen.mjs`
(recovery refused on an admin marker the gate fetches itself). `kratos/hooks/recovery-gate.jsonnet`
carries only the identity id; by the serialization gap above its `is_admin` is always false, so it
enforces nothing.

## Nothing is derived — not entry from a role, not a type from a name

**Decided.** Entry to an app comes from holding a group the app's manifest binds for access — always,
for everyone, admins included. An elevated role comes from additionally holding a role-mapped group. A
group's type comes from its bindings, never from its name.

**Why.** Both halves resist a tempting shortcut. Deriving entry from a role — a capability group
conferring access as a side effect, or the admin group implicitly granting it — means someone reading a
service's access list does not have the whole answer: entry lives partly in a different table. A rule
that must be remembered will be misremembered, so reconstructibility from one artifact is a requirement
of the model; the price, knowingly paid, is two group assignments per admin per service. That price
carries its own hazard: an admin holds two role-mapped groups, normalization sorts alphabetically, and a
first-match walk would silently hand every admin the low role, so the resolver takes the highest-ranked
declared role over the whole set instead. A naming prefix cannot double as both convention and runtime type discriminator.

**Enforced by.** `portal/src/lib/gate.ts`, `portal/src/lib/claims.ts` (highest-rank resolution),
`portal/src/lib/group-registry.ts` (binding-derived typing), `portal/scripts/gate-property.test.mjs`,
`e2e/playwright/tests/t-access-model.spec.ts`

## The durable identity key cannot be the migration key

**Decided.** The identity UUID (`sub`) is the durable key every relying party links on and must end on.
The username is only the first-link key, set per app before OIDC is enabled, and only an administrator
can change it. Email is never a link key.

**Why.** The UUID is minted at identity creation, so it exists nowhere in pre-existing application data;
the only key present in both the old data and the identity service is the human one. Most relying parties
converge anyway: match once by username, persist the UUID, match on it after. Email is rejected because
it is mutable. The UUID lives only in the identity database, so a rebuild that recreates identities breaks
every link: import identities with their ids, or budget a re-link pass. Kratos has no primitive to freeze
a trait, and an app that still re-matches on username at every sign-in would silently orphan the account
on a self-service rename, so the profile flow refuses one before it is saved.

**Enforced by.** `handleUsernameGate` in `portal/src/server/listen.mjs` on
`selfservice.flows.settings.after.profile` in `kratos/kratos.yml`; `portal/scripts/admin-port.test.mjs`,
`e2e/playwright/tests/y-username-admin-only.spec.ts`. Which key each app links on is relying-party
configuration, unenforced here.

## The passkey is the primary credential, not a second factor

**Decided.** Passkey is the primary credential everywhere. Email one-time-code is a full login method
ranked above password. Username plus password is the tertiary recovery on-ramp and the credential the
break-glass floor identities carry.

**Why.** Kratos's dedicated passkey strategy and its legacy webauthn strategy differ: the former gives
discoverable credentials and conditional UI (the usernameless one-tap flow); the latter is kept only as
a hardware second factor with passwordless disabled, so it never duplicates the primary. The fallback
ordering is deliberate: email one-time-code sits above password so a user on a new or borrowed device
gets in without typing a secret they would rarely use, landing straight in passkey enrollment.
A password credential type stays enabled because the break-glass floor must work when passkey
enrollment and email delivery are both degraded.

**Enforced by.** `e2e/playwright/tests/k-email-code-login.spec.ts` end to end. The passkey leg
(`i-passkey-register-login.spec.ts` I1) covers registration and usernameless login. UNENFORCED, like the tier
ORDER and the legacy strategy's disabled passwordless — `kratos/kratos.yml` holds those values and
nothing fails when they change.

## No password ever transits a channel

**Decided.** There is no self-service registration. An admin creates the identity with no credentials
block, mints a one-time recovery link and code in the same request, and hands both over on a
conversation that already exists with that person. The recipient establishes their own password and
passkey in their own browser.

**Why.** The invariant is not "no password exists" — it is that no password ever transits a channel.
A code emailed at creation is a delivery guess: the address is an unverified trait the admin just typed, so a mailed code is a delivery guess and a
mistyped address misroutes the secret in motion. An admin-chosen initial password is refused outright —
it is exactly a password in transit. Both link and code are required: the link alone lands on a form with an
empty code field, so a link with no code is an enrollment that looks fine from the admin's side and
dead-ends for every invitee. The admin-minted code expires slowly while self-service recovery expires fast. An enrollment message may sit unread overnight; a recovery the
user started should not.

**Enforced by.** `portal/src/lib/admin-api.ts` (identity created with no credentials block; link and
code minted together). The both-values rendering at the admin call sites is UNENFORCED.

**D1 addendum (0.5.x).** An admin can also trigger the code by email instead of hand-delivering it:
`sendInviteRecoveryEmail` (`portal/src/lib/kratos.ts`) drives Kratos's own self-service recovery flow
for the identity's on-file address, so the Kratos courier — not the portal — sends a CODE ONLY, never a
link with the code embedded, keeping the same two-channel shape. The parent decision's misrouting
rationale still applies here — the address is an admin-typed trait, and a typo sends the code to the
wrong mailbox — so this path is accepted with that risk bounded, not waived. The code is single-use and
expires within `selfservice.methods.code.config.lifespan: 15m` (`kratos/kratos.yml`) — the per-method
code window, not the 1h recovery-flow window — so a misdelivered message goes stale fast. A successful
misroute's blast radius is one fresh identity holding only its own intended group grants, never more,
because admin-marked targets are refused outright before Kratos is ever asked (`shouldRefuseRecovery`,
`portal/src/lib/access.ts`; `portal/scripts/admin-recovery-gate.test.mjs`). The send itself requires
server-checked address confirmation: the admin re-types the target address, and `confirmsInviteAddress`
(`portal/src/lib/access.ts`) rejects any submission that does not byte-equal the on-file trait before the
Kratos call — a UI-only check is not an invariant. Rate limiting on this send path is not one of those
bounds: the MEDIUM-B gap for login/recovery code floods is live and enforced
(`e2e/playwright/tests/n-rate-limits.spec.ts`, N1/N2), but it doesn't reach here — this call goes to
Kratos pod-internally, never through the public listener Caddy fronts. Enforced by
`e2e/playwright/tests/u-admin-invite-email.spec.ts` and `portal/scripts/admin-recovery-gate.test.mjs`.

## TLS is a network boundary, not an application concern

**Decided.** Applications speak plain HTTP and never load a certificate; where a real boundary exists, a
sidecar holds the cert. A hop between mutually trusted services on one private network gets network
isolation instead of mTLS or transport encryption. Issuer choice follows one question — must a browser
or device trust this out of the box — and the two roots are never cross-signed.

**Why.** One rule applied three times. In-app TLS would make every app own cert loading, renewal and error handling. An mTLS proxy in front of the identity service's admin API
is rejected the same way: mTLS earns its keep across a trust boundary, and there is none between two
containers on one isolated bridge, so it would cost a network, a proxy container and two cert-lifecycle
units to protect a hop nobody can reach. Database connections run without transport encryption for the same reason. The cost
is recorded, not hidden — "is on this network" is weaker than "presents a rostered client certificate".
Chaining an internal root under a public one fails on feasibility and blast radius alike: a public CA
will not sign intermediates for non-public use, and if it did, compromising the internal CA would
compromise the public chain. All of it is scoped to the database sharing a private network with the
services that dial it; if that stops being true, none of it transfers.

**Enforced by.** UNENFORCED here — no file in this repository declares the deployment's networks or port
publications, so nothing fails when the isolation the argument rests on regresses.

## Consent is skipped per client, never as a server default

**Decided.** Trusted first-party clients are registered with consent skipped, declared per client in
that client's manifest rather than as a server-wide default.

**Why.** Two reasons unrecoverable from the config: it keeps "which apps skip consent?" answerable by grepping
manifests rather than by reading server config and inferring "all of them, always"; and it is a
tripwire, because a default grants the skip silently to whatever gets registered next, while per-client
means a future non-first-party client must be given it explicitly. The accepted threat: the consent
screen is the one place a victim might notice "wait, I didn't open that app", so skipping it means a
stolen session mints tokens across every first-party surface silently and the session cookie becomes the
entire perimeter. The expiry condition is named: the first money-moving, irreversible or destructive
client warrants per-action re-consent or step-up regardless.

**Enforced by.** `portal/src/lib/oauth2-handlers.ts` (the consent handler honours the per-manifest flag;
a client without it bounces to the interactive screen)

## Proxy route order, and who actually needs a CORS entry

**Decided.** The portal owns the authorization server's login, consent and logout challenge routes, and
the fronting proxy must match that exact path set before any wider wildcard routing to the authorization
server. The CORS allowlist is keyed by client type: a browser SPA that fetches discovery and token
endpoints needs an entry; a redirect-flow server-side client never does.

**Why.** Both are traps that stay invisible until they fire. Inverting the proxy route order silently
breaks every login — the challenge paths get proxied to the authorization server, which does not
implement them — and the failure is total, with no degraded state to notice first. A redirect-flow
client's browser never issues a cross-origin request to the authorization server, so its origin in the
allowlist adds nothing, and credentials are allowed on the CORS config, so extra origins are not
cosmetic.

**Enforced by.** UNENFORCED — the constraint holds only in the deployed proxy config, which no gate here
can read.

## PKCE enforcement is all-or-nothing, so it is a deliberate hold

**Decided.** Global PKCE enforcement stays off, with enforcement for public clients on as a forward
guard — held deliberately rather than flipped.

**Why.** The authorization server has no per-client PKCE knob, and that absence is the constraint that
makes this a decision at all — the choice is global. "No client needs the relaxation" is not
the same statement as "every client actually sends a challenge". A confidential client that omits the challenge breaks the moment
enforcement goes on — an outage discovered at login time by every user of every affected app, not at
deploy time by a gate. Three triggers retire this debt: the non-PKCE relying party ships (keep it off,
the original constraint has returned); its rollout is abandoned (verify every deployed confidential
client, then enforce); or the authorization server ships a per-client knob.

**Enforced by.** `hydra/hydra.yml` holds the value, but UNENFORCED — nothing verifies that deployed
clients send a challenge, which is exactly the gap that makes flipping it dangerous.

## The login UI cannot run at a serverless edge

**Decided.** The login, consent and challenge UI runs inside the same private network as the identity
and authorization services, not on an edge or serverless runtime.

**Why.** The Ory admin APIs have
no authentication of their own; network position *is* the authorization, so they must be bound to a
private network, and no edge function can reach one: "reaches the admin API" and "runs at the edge" are
jointly inconsistent. Reading identity metadata, registering clients and resolving group membership all require the admin API; group membership lives in metadata the public session endpoint does not return, so even
"is this person allowed in" needs the privileged hop.

**Enforced by.** UNENFORCED — nothing prevents re-adopting an edge adapter; the failure would surface as
unreachable admin endpoints at runtime.

## Edge authorization is walked down a ladder, not argued per service

**Decided.** Which authorization a service surface gets is derived by walking a fixed ladder — use OIDC
where the app supports it natively; do not break native clients; gate sensitive browser-only surfaces
behind forward-auth — rather than decided on each service's own merits.

**Why.** The ladder is reproducible by someone who was not in the room; absent a stated rule, each service
got its own defensible answer. The non-obvious rung
is the second: a uniform edge gate is only uniform until the first native client, because such a client
carries a bearer credential rather than the browser's session cookie and the gate simply rejects it — so
the carve-out is scoped to that client's paths, not the whole service, and thereafter a "uniform" gate
is a uniform gate plus an undocumented exception. The endpoint reads a single group per call, so "entry AND
role" is two gates on one site. Finally, an ungated surface is an assignment a rung made, not an omission,
and the comment beside it is usually the only place that reason is written.

**Enforced by.** UNENFORCED. The single-value group read is visible in
`portal/src/pages/api/forward-auth.ts`, but nothing fails if a second parameter is added, and the
agreement between a declared binding and what a service's edge config gates is unobservable here.

## Cite the artifact that holds the value; never restate the value

**Decided.** A record points at the gate, test or config file that holds a value instead of copying it,
and every normative "must" either names the file that fails when it is violated or carries an explicit
unenforced marker.

**Why.** Counts, addresses, hostnames, rosters, tallies and line numbers rot silently, while a gate
cannot — it fails. Claiming an enforcer that does not exist is worse than admitting there is none.

**Enforced by.** `scripts/check-purity.sh`, over the whole index. Each check states its own scope at
its call site, and restating that list here would be the rot this entry is about.
