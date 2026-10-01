// Admin-listener runtime surface. listen.mjs is plain ESM under bare `node` and
// cannot import the TypeScript libs, so this is the bundle entry (esbuild, see
// build:admin-runtime) it lazily imports at bind time for the Kratos admin
// client, without delegating to the public Astro handler. The hook verdicts
// live here so they share decideAccess and parseIdentity with every other gate.

export { getIdentity, listSessions, revokeSession, prunePasskeyNames } from '../lib/admin-api';
export { decideAccess } from '../lib/gate';
export { secondFactorChangeVerdict, SECOND_FACTOR_KEEP, SECOND_FACTOR_UNAVAILABLE } from '../lib/second-factor-gate';
export { emailChangeVerdict, EMAIL_CHANGE_REFUSAL } from '../lib/profile-gate';
export { KRATOS_ADMIN_URL, HYDRA_ADMIN_URL } from '../lib/constants';
