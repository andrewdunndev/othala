// Admin-listener runtime surface (CU3).
//
// The dual-listener's admin port (src/server/listen.mjs) is plain ESM and
// runs under bare `node` (npm start), so it cannot import the TypeScript
// lib modules directly. This file is the single bundle entry the build
// compiles to `dist/server/admin-runtime.mjs` (esbuild, see the
// build:admin-runtime npm script); listen.mjs lazily imports it at bind
// time to give the admin-port handlers the one Kratos admin client (the SDK
// wrappers in admin-api.ts) — WITHOUT delegating to the public Astro handler
// (the two muxes stay disjoint). The second-factor gate's verdict lives here
// because it shares hasSecondFactor with the step-up check.

export { getIdentity, listSessions, revokeSession } from '../lib/admin-api';
export { isAdminMarker } from '../lib/admin-auth';
export { secondFactorChangeVerdict, SECOND_FACTOR_KEEP, SECOND_FACTOR_UNAVAILABLE } from '../lib/second-factor-gate';
export { emailChangeVerdict, EMAIL_CHANGE_REFUSAL } from '../lib/profile-gate';
