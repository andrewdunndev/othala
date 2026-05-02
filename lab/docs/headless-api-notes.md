# Kanidm headless auth flow API — capability map

Research date: 2026-05-02. Targeting kanidm master / 1.10.x series.

## Summary

A fully-custom Astro/Tailwind login UI driving kanidm's `/v1/auth/*` JSON
API directly is **not viable today** without per-deployment patches.
The auth state machine itself (`AuthStep::Init`/`Begin`/`Cred` over
`POST /v1/auth`) is well-typed, exposed by `kanidm_client`, and used by
the CLI. The blockers are three structural choices the project has
made and reaffirmed as recently as April 2026:

1. **No CORS** on any endpoint (the PR to add it, #2980, was closed
   April 30, 2026). The auth API is not callable cross-origin from a
   browser.
2. **Session cookies are scoped to a single host**
   (`Cookie::set_domain(state.domain)`), and the kanidm book mandates
   that kanidm own its hostname at `/`. A cookie set on
   `idm.example.com` is not readable from `home.example.com`.
3. **The current Web UI does not consume `/v1/auth` over HTTP at all**;
   it calls `state.qe_r_ref.handle_auth(...)` in-process from
   Askama+HTMX server views. So the v1 auth API has no in-tree browser
   consumer driving its evolution toward browser-friendliness.

Verdict: **RED** for "fully custom Astro frontend on a different
subdomain calling kanidm directly from JS". Verdict: **YELLOW** for
"home portal as an OAuth2 RP that hands login off to kanidm's hosted
UI" — that is fully supported and is the project's recommended shape.

## API surface

### Login flow (POST /v1/auth)

**Endpoints** (from `server/core/src/https/v1.rs`):

```
POST /v1/auth         -> auth handler
POST /v1/reauth       -> reauth handler
GET  /v1/auth/valid   -> auth_valid
GET  /v1/logout       -> logout
```

There are no separate `/begin` / `/continue` paths. The whole flow
multiplexes through `POST /v1/auth` with a session id carried in either
the `KSESSIONID` header or the `kanidm-auth-session-id` cookie
(`COOKIE_AUTH_SESSION_ID`). The state machine is encoded in the request
body.

**Wire types** (from `proto/src/v1/auth.rs`):

```rust
pub struct AuthRequest { pub step: AuthStep }

pub enum AuthStep {
    Init(String),
    Init2 { username: String, issue: AuthIssueSession, privileged: bool },
    Begin(AuthMech),
    Cred(AuthCredential),
}

pub struct AuthResponse { pub sessionid: Uuid, pub state: AuthState }

pub enum AuthState {
    Choose(Vec<AuthMech>),
    Continue(Vec<AuthAllowed>),
    Denied(String),
    Success(String),
}

pub enum AuthMech {
    Anonymous, Password, PasswordBackupCode,
    PasswordTotp, PasswordSecurityKey, Passkey, OAuth2Trust,
}

pub enum AuthAllowed {
    Anonymous, BackupCode, Password, Totp,
    SecurityKey(RequestChallengeResponse),
    Passkey(RequestChallengeResponse),
}

pub enum AuthCredential {
    Anonymous,
    Password(String),
    Totp(u32),
    SecurityKey(Box<PublicKeyCredential>),
    BackupCode(String),
    Passkey(Box<PublicKeyCredential>),
}

pub enum AuthIssueSession { Token, Cookie }
```

**Flow:**

1. Client `POST /v1/auth` with `AuthStep::Init2 { username, issue, privileged }`.
2. Server returns `AuthState::Choose(Vec<AuthMech>)`.
3. Client `POST /v1/auth` with `AuthStep::Begin(AuthMech::Passkey)` (etc).
4. Server returns `AuthState::Continue(Vec<AuthAllowed>)`. For passkey
   / security key, the `AuthAllowed::Passkey(RequestChallengeResponse)`
   variant carries a `webauthn-rs` `RequestChallengeResponse`.
5. Client `POST /v1/auth` with `AuthStep::Cred(AuthCredential::Passkey(...))`.
6. Server returns `AuthState::Success(token)` or `AuthState::Denied(_)`.

**Auth mechanisms supported headless:** all six interactive mechanisms
(`Password`, `PasswordBackupCode`, `PasswordTotp`, `PasswordSecurityKey`,
`Passkey`, `Anonymous`). `kanidm_client` exercises all of them, so the
wire format is real and used.

**WebAuthn shape:** the challenge is `webauthn_rs_proto::RequestChallengeResponse`
(for auth) and `CreationChallengeResponse` (for enrollment).
`webauthn-rs` is a sibling project from the same author. The JSON
shape is compatible with `navigator.credentials.get()` after the usual
base64url unwrapping. `kanidm_client` round-trips
`webauthn_authenticator_rs::PublicKeyCredential` back to the server.

**Documentation status:** the design doc at
`developers/designs/authentication_flow.html` describes the state
machine in prose. It does **not** document HTTP paths, JSON shapes, or
session-id transport. The OpenAPI schema at `/docs/v1/openapi.json`
(generated via utoipa) is the only machine-readable surface. Issue
[#2951](https://github.com/kanidm/kanidm/issues/2951) ("REST Api
unusable with current docs") is open and labelled `documentation`,
`api`. The reporter ran into HTTP 500s trying to follow the docs and
was told the API "appears designed only for internal client
consumption."

**Stability:** no semver guarantee statement found in the book or
release notes. The proto module's mod doc does claim "stability and
forward compatibility for this v1 API" per the deepwiki extract, but I
could not surface that text directly. In practice the wire types
change rarely (`AuthStep::Init2` was added to support privileged
sessions; `AuthIssueSession` was added to support cookie issuance).

**Verdict: YELLOW for the auth API itself.** The endpoint exists, is
typed, is consumed by `kanidm_client` and `kanidm-cli`, and works.
What makes it red for browser BYO-UI is the surrounding constraints
(CORS, cookie scope), not the endpoint design.

### OAuth2 authorize handoff

**Behavior** (from `server/core/src/https/oauth2.rs` and
`server/core/src/https/views/oauth2.rs`):

```
GET  /oauth2/authorise           -> oauth2_authorise_get
POST /oauth2/authorise           -> oauth2_authorise_post
GET  /oauth2/authorise/permit    -> oauth2_authorise_permit_get
POST /oauth2/authorise/permit    -> oauth2_authorise_permit_post
POST /oauth2/token               -> oauth2_token_post
```

The view handler `view_index_get` calls
`state.qe_r_ref.handle_oauth2_authorise(client_auth_info, ...)`, where
`client_auth_info` is populated from the `COOKIE_BEARER_TOKEN` cookie
(or `Authorization: Bearer ...`). The backend resolves three outcomes:

- `AuthenticationRequired` → render the login view inline (no HTTP
  redirect; the OAuth2 request is preserved through the login flow).
- `ConsentRequested` → render consent form.
- `Permitted` → redirect to the RP `redirect_uri` with the code.

So **yes**, a user with a valid kanidm session who is redirected to
`/oauth2/authorise?...` will be carried straight to consent (or auto-
permitted if pre-consented). The session cookie is honored. This is
the "session, then redirect" pattern Kratos calls "browser flow," and
it works.

The 401 path on the JSON API endpoint
(`POST /oauth2/authorise` for confidential clients) returns
`WWW-Authenticate: Bearer` rather than redirecting; the comment in the
source says "this will trigger our ui to auth and retry."

**Verdict: GREEN.** OAuth2 RP integration works exactly as expected.
A custom Astro home portal can absolutely sit at
`home.example.com` and OIDC-redirect users to `idm.example.com` for
login. This is the project's intended shape.

### Session cookies

**Names** (from `server/core/src/https/views/cookies.rs` and
`auth_session_state_management()` in `v1.rs`):

- `kanidm-auth-session-id` (`COOKIE_AUTH_SESSION_ID`) — transient
  state during the multi-step auth flow. `SameSite=Strict`, `HttpOnly`,
  `Secure`.
- `kanidm-bearer-token` (`COOKIE_BEARER_TOKEN`) — issued on
  `AuthState::Success` when `AuthIssueSession::Cookie` was requested.
  `SameSite=Lax`, `HttpOnly`, `Secure`, `Path=/`.
- `kanidm-cu-session-token` (`COOKIE_CU_SESSION_TOKEN`) — credential
  update session.

**Domain attribute:**

```rust
bearer_cookie.set_domain(state.domain.clone());
```

`state.domain` is the configured `domain` from kanidm's server config —
a single hostname, not a parent. Kanidm does not set the cookie with a
leading dot (e.g., `.example.com`) and the source has no code path
that would do so. The book's "Choosing a Domain Name" page reinforces
this: "Kanidm must be the _only_ thing running on a hostname, served
from `/`."

**Cross-subdomain support:** **no, not without modifying kanidm.**
Three things break the home-portal-shares-cookies-with-IDM model:

1. The `Domain` attribute is set to the exact host. To share with
   sibling subdomains, kanidm would need to write `.example.com` (or
   parent), which it does not.
2. Even if you patched it, `SameSite=Lax` on the bearer cookie means
   cross-site `fetch()` from `home.example.com` JS to
   `idm.example.com` would not include the cookie unless the request
   was a navigation or top-level `GET`.
3. `HttpOnly` means JS at `home.example.com` cannot read the cookie to
   forward it as `Authorization: Bearer`.

**Verdict: RED for cross-subdomain cookie sharing.** Use OAuth2 RP
flow instead.

### Self-service flows

The credential update API is a parallel state machine to auth, with the
same shape (session token + step requests).

**Endpoints** (from `server/core/src/https/v1.rs`):

```
POST /v1/credential/_exchange_intent   -> credential_update_exchange_intent
POST /v1/credential/_status            -> credential_update_status
POST /v1/credential/_update            -> credential_update_update
POST /v1/credential/_commit            -> credential_update_commit
POST /v1/credential/_cancel            -> credential_update_cancel
GET  /v1/person/{id}/_credential/_update         -> begin update as admin
GET  /v1/person/{id}/_credential/_update_intent  -> mint reset token
GET  /v1/person/{id}/_credential/_update_intent/{ttl}
POST /v1/person/{id}/_credential/_update_intent_send
```

**Wire types** (from `proto/src/internal/credupdate.rs`):

```rust
pub enum CURequest {
    PrimaryRemove,
    PasswordQualityCheck(String),
    Password(String),
    CancelMFAReg,
    TotpGenerate, TotpVerify(u32, String), TotpAcceptSha1, TotpRemove(String),
    BackupCodeGenerate, BackupCodeRemove,
    PasskeyInit, PasskeyFinish(String, RegisterPublicKeyCredential), PasskeyRemove(Uuid),
    AttestedPasskeyInit, AttestedPasskeyFinish(String, RegisterPublicKeyCredential), AttestedPasskeyRemove(Uuid),
    UnixPasswordRemove, UnixPassword(String),
    SshPublicKey(String, SshPublicKey), SshPublicKeyRemove(String),
}

pub struct CUStatus {
    pub spn: String, pub displayname: String,
    pub ext_cred_portal: CUExtPortal,
    pub mfaregstate: CURegState,
    pub can_commit: bool,
    pub warnings: Vec<CURegWarning>,
    pub primary: Option<CredentialDetail>, pub primary_state: CUCredState,
    pub passkeys: Vec<PasskeyDetail>, pub passkeys_state: CUCredState,
    pub attested_passkeys: Vec<PasskeyDetail>, pub attested_passkeys_state: CUCredState,
    pub attested_passkeys_allowed_devices: Vec<String>,
    pub unixcred: Option<CredentialDetail>, pub unixcred_state: CUCredState,
    pub sshkeys: BTreeMap<String, SshPublicKey>, pub sshkeys_state: CUCredState,
}

pub enum CURegState {
    None,
    TotpCheck(TotpSecret), TotpTryAgain, TotpNameTryAgain(String), TotpInvalidSha1,
    BackupCodes(Vec<String>),
    Passkey(CreationChallengeResponse),
    AttestedPasskey(CreationChallengeResponse),
}
```

**Passkey enrollment (headless):** mechanically supported. Send
`CURequest::PasskeyInit`, receive `CURegState::Passkey(CreationChallengeResponse)`,
hand to `navigator.credentials.create()`, wrap the response in
`CURequest::PasskeyFinish(label, RegisterPublicKeyCredential)`, then
`POST /v1/credential/_commit`.

**Credential change:** same session machine — `CURequest::Password`,
`PasswordQualityCheck`, `TotpGenerate` + `TotpVerify`, etc.

**Recovery:** the intent-token flow
(`person_id_credential_update_intent_send`) sends a reset link via
the configured external credential portal. The token can then be
exchanged at `/v1/credential/_exchange_intent` to start a session
without prior auth — this is the only auth-less path into the
credential machine.

**Verdict: YELLOW.** The endpoints exist and are exercised by
`kanidm-cli` (`idm_account_credential_update_passkey_init/_finish` etc.).
But same constraints as login: no CORS, cookies scoped to the kanidm
host. So you can drive these from a server-side Astro endpoint that
proxies to kanidm with a bearer token, but not from browser JS at a
different origin.

### CORS / cross-origin

**Status: not implemented.**

- `server/core/src/https/middleware/security_headers.rs` sets
  `X-Content-Type-Options`, `Permissions-Policy`, `Referrer-Policy`,
  and `Content-Security-Policy`. **No `Access-Control-Allow-Origin`,
  no preflight handling.**
- The router in `server/core/src/https/mod.rs` does not install
  `tower-http::cors::CorsLayer`.
- [Issue #2863](https://github.com/kanidm/kanidm/issues/2863) ("Add
  CORS headers to the userinfo endpoint") is **open** and tagged
  "🏗 In progress" but with no maintainer comments visible.
- [PR #2980](https://github.com/kanidm/kanidm/pull/2980) ("Add CORS
  for REST API") was **closed April 30, 2026**. Firstyear's stated
  reason: *"if you want to make a custom ui, it has to be a subdomain
  of the IDM — too many things have to change otherwise."* (Note that
  even subdomain co-location does not solve cross-origin in the
  browser; this comment is the maintainer's signal that BYO-browser-UI
  is not a supported path.)

**Implications:** any browser-side `fetch('https://idm.example.com/v1/auth', ...)`
from `home.example.com` JS will be blocked at the CORS preflight stage.
A custom login UI is only viable if it is served from the same origin
as kanidm itself, which the book forbids ("Kanidm must be the only
thing running on a hostname, served from `/`").

**Workarounds that would unblock browser BYO-UI:**

1. Run a same-origin reverse proxy that fronts both kanidm and the
   custom UI on one host. This violates the book's hostname-isolation
   guidance and probably breaks `/.well-known/webauthn-endpoints`.
2. Run a server-side proxy in your Astro app that forwards to kanidm
   with a privileged service-account bearer token. This works but
   defeats the point: you're now writing the IDM, you've just put
   kanidm behind it.
3. Patch kanidm to install a configurable `CorsLayer` and set the
   bearer cookie domain to the parent. This is the contribution
   shape (see "If RED" below).

## Reference clients

**`kanidm_client` crate** (`libs/client/src/lib.rs`,
docs.rs/kanidm_client/1.10.0):

The crate is the project's blessed HTTP client and is what `kanidm-cli`
and `kanidm-unixd` consume. Relevant methods:

- `auth_step_init` → `POST /v1/auth` with `AuthStep::Init2`
- `auth_step_begin` → `POST /v1/auth` with `AuthStep::Begin(mech)`
- `auth_step_password` → `POST /v1/auth` with `AuthStep::Cred(Password(...))`
- `auth_step_passkey_complete` → `POST /v1/auth` with
  `AuthStep::Cred(Passkey(pkc))`

The client builder enables `cookie_store(true)` and prefers bearer
tokens over cookies (`response.bearer_auth(token)`). The client
supports both `AuthIssueSession::Token` (token in JSON body) and
`AuthIssueSession::Cookie` (token also set as `kanidm-bearer-token`
cookie). For a non-browser BYO-UI (e.g., a server-side Astro adapter)
this is the API to model against.

**`kanidm-cli` (`tools/cli/src/cli/person.rs`):**

The CLI for credential management calls (and these are the methods you
would mirror for self-service in a custom UI):

- `idm_account_credential_update_begin`
- `idm_account_credential_update_exchange` (intent-token flow)
- `idm_account_credential_update_status`
- `idm_account_credential_update_set_password`
- `idm_account_credential_update_passkey_init` /
  `_passkey_finish` / `_passkey_remove`
- `idm_account_credential_update_attested_passkey_init` / `_finish` / `_remove`
- `idm_account_credential_update_init_totp` / `_check_totp`
- `idm_account_credential_update_sshkey_add`
- `idm_account_credential_update_commit`

These are thin wrappers over the `/v1/credential/_*` endpoints listed
above.

**Web UI as a reference:** **the in-tree Web UI is no longer a useful
HTTP-API reference.** As of 1.4.0 (Nov 2024), kanidm's UI was rewritten
from Yew/WASM to Askama+HTMX server-side rendering (discussion
[#3187](https://github.com/kanidm/kanidm/discussions/3187)). The
handlers in `server/core/src/https/views/login.rs`
(`view_login_begin_post`, `view_login_pw_post`, `view_login_passkey_post`,
etc.) call `state.qe_r_ref.handle_auth(...)` and
`state.qe_w_ref.handle_logout(...)` **in-process**, not over HTTP.
They do not POST to `/v1/auth`. This means:

1. There is no in-tree fetch-driven auth client to copy from. Wire
   shapes have to be inferred from `proto/` types and `kanidm_client`.
2. The Web UI's HTMX endpoints (`/ui/login/*`) are an HTML view layer
   bolted directly onto the IDM core, not an alternate frontend
   contract. Re-using them outside the kanidm process is not a path.
3. Future kanidm releases optimizing the HTMX UI may not stress-test
   the JSON `/v1/auth` surface, so behavior drift between
   `handle_auth(...)` and the JSON wrapper is plausible.

For an external repo that builds a Yew-based replacement frontend, see
[bluelinden/kanidm-with-ui](https://github.com/bluelinden/kanidm-with-ui).
This is a fork (not a parallel client), so it inherits same-origin —
it has not solved the cross-origin problem either.

## Gaps and footguns

1. **No CORS, by maintainer choice.** The PR was closed in April 2026
   with the explicit "subdomain of the IDM" guidance. Browser BYO-UI
   served from a different origin is dead in the water.
2. **Bearer cookie domain is the kanidm host, not a parent.** Even if
   CORS were on, a JS app at `home.example.com` could not read or
   forward the `kanidm-bearer-token` cookie set on `idm.example.com`
   (different origin AND `HttpOnly`).
3. **The book forbids co-hosting on the same hostname.** "Kanidm must
   be the _only_ thing running on a hostname, served from `/`." So the
   "host the custom UI on the same origin" workaround is officially
   off-limits.
4. **Web UI rewrite (1.4.0) decoupled the in-tree UI from the JSON
   API.** The HTMX views call internal functions, not `/v1/auth`. The
   JSON API has lost its in-tree browser consumer, so its evolution
   is driven by `kanidm-cli` and `kanidm-unixd` only.
5. **Documentation gap.** Issue
   [#2951](https://github.com/kanidm/kanidm/issues/2951) is open and
   confirms the API is "designed only for internal client consumption."
   No curl-level walkthrough of the auth flow exists in the book; the
   only design doc covers the abstract state machine.
6. **No semver promise on `/v1`.** The proto module claims "stability"
   in its rustdoc, but no public statement exists in the book or
   release notes. `AuthStep::Init2` (with `privileged`) was added
   recently; legacy clients pinning to `Init(String)` got a soft path
   forward, but there is no formal compat policy.
7. **WebAuthn RP ID is the kanidm host.** A passkey enrolled while
   relying-party-id = `idm.example.com` cannot be asserted by a
   browser UI running at `home.example.com` even if all the other
   problems were solved. Passkeys are origin-bound on the browser
   side; the auth UI must be served from (or at minimum
   navigate-redirect from) the same origin as kanidm.
8. **`SameSite=Lax` on the bearer cookie** means even top-level
   navigation from `home.example.com` to `idm.example.com` carrying
   only a `fetch` would fail to attach it. OAuth2 redirects do work
   because they are top-level GETs.
9. **Maintainer position is firmly anti-fragmentation.** Discussion
   [#4096](https://github.com/kanidm/kanidm/discussions/4096):
   *"We have people trying to implement 3rd party UI's instead of
   contributing to upstream. That's what we mean by fragmented."*
   A patch to support BYO browser UI is unlikely to be accepted on
   architectural grounds alone — would need a concrete security story.

## Layer 2 viability verdict

**RED — major upstream work needed before BYO browser UI is reasonable.**

For dunn.dev specifically, the practical consequence:

- Custom Astro/Tailwind login form at `home.dunn.dev` calling
  `idm.dunn.dev/v1/auth` directly: **not possible.** Blocked by
  CORS, cookie scope, and WebAuthn origin binding.
- Custom Astro tile-launcher at `home.dunn.dev` that uses kanidm
  as an OIDC IDP and hands login off to the kanidm hosted UI on
  `idm.dunn.dev`: **fully supported, recommended path.** OAuth2
  authorize endpoint honors the existing kanidm session, so users
  who are already logged in to kanidm flow through to consent (or
  auto-permit) without re-prompting.
- Custom Astro **passkey enrollment / password change** UI: same
  story. Use a credential reset intent token to redirect the user
  to kanidm's hosted credential portal, or proxy through a
  server-side Astro endpoint with a service account.

If the dunn.dev requirement is a unified visual identity for the
home portal _including_ the login page, the cheapest path is
theming kanidm itself (CSS via `override.css`) rather than building
a parallel UI. The next-cheapest is templating-level contribution to
kanidm's own Askama+HTMX views.

## If RED: contribution shape

A first-class headless login flow contribution to kanidm would need to:

1. **Add a configurable CORS allowlist** (`cors_allowed_origins`
   in server config), wired with `tower-http::cors::CorsLayer`.
   Apply only to `/v1/auth`, `/v1/auth/valid`, `/v1/credential/_*`,
   `/v1/self`, `/oauth2/userinfo`, and the OAuth2 token/jwks
   endpoints. Keep CORS off elsewhere. Document that enabling
   it widens attack surface and should be paired with a strict
   CSP on the calling origin. PR #2980 is the prior art; revive
   with a tighter scope and Firstyear-acceptable security writeup.
2. **Allow bearer-cookie domain to be configurable** to a parent
   suffix (`idm_cookie_domain` in server config, defaulting to the
   exact host). Document the public-suffix-list footgun the book
   already discusses on "Choosing a Domain Name."
3. **Drop `SameSite=Lax` to `SameSite=None; Secure`** when CORS is
   in use, behind the same flag. Required for cross-site cookie
   attachment.
4. **Document the curl-level auth flow** in the book under
   "Integrations / API" — fold in the resolution of issue #2951.
   Include a working `curl | jq` walkthrough for each `AuthMech`.
5. **Mark `/v1/auth`, `/v1/credential/_*`, `/v1/self` as a stable
   public surface** in the book with a semver-on-breaking-changes
   pledge. Without this, downstream BYO-UI authors carry the
   compat risk.
6. **Optional: a `/v1/auth/begin` and `/v1/auth/continue` REST
   facade** with explicit URL-segmented steps. The current
   single-endpoint multiplexed state machine is a bit Rust-enum
   friendly, less REST friendly. This would make the flow more
   discoverable from Swagger UI alone. Probably bikesheddable.

The CORS+cookie+SameSite work is the load-bearing part. Items 4–6
are documentation and ergonomics. Without items 1–3, no amount of
documentation makes browser BYO-UI possible.

A more conservative contribution that the maintainer is more likely
to accept: **stay inside kanidm's hostname** and contribute to the
in-tree Askama+HTMX UI. This is the path Firstyear has explicitly
asked for in discussions
[#3187](https://github.com/kanidm/kanidm/discussions/3187) and
[#4096](https://github.com/kanidm/kanidm/discussions/4096).

## Sources

- Authentication flow design: <https://kanidm.github.io/kanidm/master/developers/designs/authentication_flow.html>
- Authentication & credentials: <https://kanidm.github.io/kanidm/stable/accounts/authentication_and_credentials.html>
- Choosing a domain name: <https://kanidm.github.io/kanidm/stable/choosing_a_domain_name.html>
- REST interface design: <https://kanidm.github.io/kanidm/master/developers/designs/rest_interface.html>
- DeepWiki Web UI and API: <https://deepwiki.com/kanidm/kanidm/2.5-web-ui-and-api>
- DeepWiki credential management: <https://deepwiki.com/kanidm/kanidm/3.2-credential-management>
- `proto/src/v1/auth.rs`: <https://raw.githubusercontent.com/kanidm/kanidm/master/proto/src/v1/auth.rs>
- `proto/src/internal/credupdate.rs`: <https://raw.githubusercontent.com/kanidm/kanidm/master/proto/src/internal/credupdate.rs>
- `server/core/src/https/v1.rs` (route table): <https://raw.githubusercontent.com/kanidm/kanidm/master/server/core/src/https/v1.rs>
- `server/core/src/https/mod.rs` (router): <https://raw.githubusercontent.com/kanidm/kanidm/master/server/core/src/https/mod.rs>
- `server/core/src/https/oauth2.rs`: <https://raw.githubusercontent.com/kanidm/kanidm/master/server/core/src/https/oauth2.rs>
- `server/core/src/https/views/oauth2.rs`: <https://raw.githubusercontent.com/kanidm/kanidm/master/server/core/src/https/views/oauth2.rs>
- `server/core/src/https/views/login.rs`: <https://raw.githubusercontent.com/kanidm/kanidm/master/server/core/src/https/views/login.rs>
- `server/core/src/https/middleware/security_headers.rs`: <https://raw.githubusercontent.com/kanidm/kanidm/master/server/core/src/https/middleware/security_headers.rs>
- `libs/client/src/lib.rs` (kanidm_client): <https://raw.githubusercontent.com/kanidm/kanidm/master/libs/client/src/lib.rs>
- `kanidm_client` crate docs (1.10.0): <https://docs.rs/kanidm_client/latest/kanidm_client/>
- Issue #2863 — Add CORS headers to userinfo (open): <https://github.com/kanidm/kanidm/issues/2863>
- PR #2980 — Add CORS for REST API (closed Apr 30 2026): <https://github.com/kanidm/kanidm/pull/2980>
- Issue #2951 — REST API unusable with current docs (open): <https://github.com/kanidm/kanidm/issues/2951>
- Discussion #3187 — New (1.4.0) web UI: <https://github.com/kanidm/kanidm/discussions/3187>
- Discussion #4096 — WebUI improvements: <https://github.com/kanidm/kanidm/discussions/4096>
- bluelinden/kanidm-with-ui (third-party Yew fork): <https://github.com/bluelinden/kanidm-with-ui>
