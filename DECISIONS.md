# Decisions

Rulings a change must not reverse. The reasoning is in git history; the enforcer is named or UNENFORCED.

- `whoami.required_aal` stays `aal1`; step-up is per flow in the app. Enforced by `portal/scripts/forward-auth.test.mjs`, `portal/scripts/contract.test.mjs`, `e2e/playwright/tests/v-app-stepup.spec.ts`.
- Step-up is per client: `consent.skip_step_up: true` lets that OIDC client accept an aal1 session signed in by a passkey alone (a password or emailed-code sign-in still steps up), for any identity, admin-marked included; portal admin pages, settings, device grants, forward-auth, the landing and every unflagged client keep aal2. Enforced by `portal/scripts/gate.test.mjs`, `e2e/playwright/tests/vc-client-stepup-optout.spec.ts`.
- Forward-auth answers 200/401/403/503; an outage is never a 403; the group is a query parameter, never a header; HEAD = GET. Enforced by `portal/scripts/forward-auth.test.mjs`.
- Admin authority is the boolean `metadata_admin.admin`, never a group or an env allowlist; the portal is its only validator. Enforced by `portal/src/lib/metadata-admin.ts`, `portal/src/lib/identity-facts.test.ts`.
- Entry comes only from a manifest's access binding, admins included; a group's type comes from its binding, never its name; role is the highest-ranked declared role over all held groups. Enforced by `portal/scripts/gate-property.test.mjs`, `e2e/playwright/tests/t-access-model.spec.ts`.
- `sub` is the durable link key; username is the first-link key, admin-only to change; email is never a link key. Enforced by `e2e/playwright/tests/y-username-admin-only.spec.ts`.
- Passkey primary, email code above password, password kept for break-glass. Enforced by `e2e/playwright/tests/k-email-code-login.spec.ts`; the tier order is UNENFORCED.
- No self-registration; an admin creates the identity with no credentials and mints link and code together; no admin-set password. Enforced by `portal/src/lib/admin-api.ts`, `portal/scripts/admin-api-create.test.mjs`.
- No in-app TLS or in-pod mTLS; isolation is the boundary. UNENFORCED.
- Consent skip is per client in its manifest, never a server default. Enforced by `portal/src/lib/oauth2-handlers.ts`.
- The portal's challenge routes match before any wider Hydra route. UNENFORCED.
- Global PKCE enforcement stays off until every confidential client sends a challenge. UNENFORCED (`hydra/hydra.yml`).
- The login UI runs beside the admin APIs, never on a serverless edge. UNENFORCED.
- Edge authorization: OIDC where native, keep native clients working, forward-auth for browser-only surfaces; one group per forward-auth call. UNENFORCED.
- The portal renders its own auth UI and never branches on Kratos UI flags or node groups. UNENFORCED.
- Admin listings fetch one capped page and never read a total count (`listIdentities`, `portal/src/lib/admin-api.ts`). UNENFORCED.
- Every `metadata_admin` write goes through `validateMetadataAdmin` (`portal/src/lib/metadata-admin.ts`). UNENFORCED.
- Sessions slide: `session.lifespan: 2160h`, `earliest_possible_extend: 2136h` and `ttl.refresh_token: 2160h`. The portal extends and relays the cookie on the landing and `/oauth2/login`, never on forward-auth and not past 365d since `authenticated_at`; admins slide too, and admin freshness is unchanged. The 365d cap covers app refresh chains: Hydra's `oauth2.token_hook` refuses a refresh with no active Kratos session, at the cost that every refresh depends on the portal being up (fail closed). Enforced by `portal/scripts/session-slide.test.mjs`, `e2e/playwright/tests/vs-session-slide.spec.ts`.
