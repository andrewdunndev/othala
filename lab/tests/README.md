# lab/tests (LEGACY — pre-Ory)

These Playwright specs target **Authentik**, the pre-pivot substrate.
They reference `akadmin`, `dunn-authentication` flow URLs, and the
`AUTHENTIK_BOOTSTRAP_PASSWORD` env var. None of that maps to the
current Ory Kratos + Hydra stack.

## Status

Stale. Don't run them; they will fail against the live substrate.

## Replacement path

- **Substrate health + apply-clients + recovery-gate semantics**:
  `lab/ci/smoke.sh` (runs in the CI lab on every push/MR/tag).
- **Portal unit tests**: `portal/scripts/*.test.mjs` (38 tests, runs
  via `test-portal` CI job).
- **Browser-driven OIDC end-to-end**: not yet rewritten for Ory.
  When this matters, add new Playwright specs targeting:
   - `auth.dunn.dev/auth/login` (Kratos password + WebAuthn flows)
   - `auth.dunn.dev/admin/users` (admin UI, AAL2 step-up)
   - `auth.dunn.dev/apps/<slug>` (per-app detail page rendering)
   - Cross-app OIDC: `keep.dunn.dev` SSO sign-in via Hydra
  Models them on `apps.spec.ts` structure but with Ory selectors.

## Why preserved

Historical reference for the test selectors + flow assertions, if
some future contributor wants to mine the pattern. Delete when the
Ory replacement specs land.
