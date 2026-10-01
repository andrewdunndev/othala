// Fixed deployment topology and policy, each defined once. Nothing here reads the environment.

/** Kratos public API on the golden service name; server-side calls stay off the edge and its rate limits. */
export const KRATOS_PUBLIC_URL = 'http://kratos:4433';
/** Kratos admin API on the golden service name; unauthenticated, network isolation is the control. */
export const KRATOS_ADMIN_URL = 'http://kratos:4434';
/** Hydra admin API on the golden service name; unauthenticated, network isolation is the control. */
export const HYDRA_ADMIN_URL = 'http://hydra:4445';
/** Where the golden compose mounts the app manifests. */
export const MANIFEST_DIR = '/etc/portal/manifests';
/** Group the admin console files a new identity under and tiles fall back to. */
export const DEFAULT_GROUP = 'everyone';
/** Identity groups the admin UI offers: 'admin' first, then the default group. App access groups come from the manifests. */
export const IDENTITY_GROUPS: readonly string[] = ['admin', DEFAULT_GROUP];
/** Session-age window for the admin step-up; separate from Kratos's 5m privileged window. */
export const ADMIN_FRESHNESS_HOURS = 1;
