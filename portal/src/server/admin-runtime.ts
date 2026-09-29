// Admin-listener runtime surface (CU3).
//
// The dual-listener's admin port (src/server/listen.mjs) is plain ESM and
// runs under bare `node` (npm start), so it cannot import the TypeScript
// lib modules directly. This file is the single bundle entry the build
// compiles to `dist/server/admin-runtime.mjs` (esbuild, see the
// build:admin-runtime npm script); listen.mjs lazily imports it at bind
// time to wire the in-process revoke fan-out into the admin-port handlers
// — WITHOUT delegating to the public Astro handler (the two muxes stay
// disjoint).
//
// The recovery and username gates read the stored identity themselves; the
// second-factor gate's verdict lives here because it shares hasSecondFactor
// with the step-up check.

export { revokeSubject, RevokeError } from '../lib/revoke';
export type { RevokeResult, RevokeDependency } from '../lib/revoke';
export { secondFactorChangeVerdict, SECOND_FACTOR_KEEP, SECOND_FACTOR_UNAVAILABLE } from '../lib/second-factor-gate';
