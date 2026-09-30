// Admin-listener runtime surface. listen.mjs is plain ESM under bare `node` and
// cannot import the TypeScript libs, so this is the bundle entry (esbuild, see
// build:admin-runtime) it lazily imports at bind time for the Kratos admin
// client, without delegating to the public Astro handler. The second-factor
// gate's verdict lives here because it shares hasSecondFactor with step-up.

export { getIdentity, listSessions, revokeSession } from '../lib/admin-api';
export { isAdminMarker } from '../lib/admin-auth';
export { secondFactorChangeVerdict, SECOND_FACTOR_KEEP, SECOND_FACTOR_UNAVAILABLE } from '../lib/second-factor-gate';
export { emailChangeVerdict, EMAIL_CHANGE_REFUSAL } from '../lib/profile-gate';
