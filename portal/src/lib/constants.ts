// Fixed deployment topology and policy, each defined once. Nothing here reads the environment.

/** Kratos public API on the golden service name; server-side calls stay off the edge and its rate limits. */
export const KRATOS_PUBLIC_URL = 'http://kratos:4433';
/** Kratos admin API on the golden service name; unauthenticated, network isolation is the control. */
export const KRATOS_ADMIN_URL = 'http://kratos:4434';
/** Hydra admin API on the golden service name; unauthenticated, network isolation is the control. */
export const HYDRA_ADMIN_URL = 'http://hydra:4445';
/** Where the golden compose mounts the app manifests. */
export const MANIFEST_DIR = '/etc/portal/manifests';
/** Where the image carries the Ory policy files the render reads. */
export const POLICY_DIR = '/usr/share/othala';
/** Where the render writes the Ory configs; kratos/ mounts at /etc/config/kratos, hydra/ at /etc/config/hydra. */
export const RENDER_DIR = '/run/othala';
/** Group the admin console files a new identity under and tiles fall back to. */
export const DEFAULT_GROUP = 'everyone';
/** Identity groups the admin UI offers as household groups. App access groups come from the manifests. */
export const IDENTITY_GROUPS: readonly string[] = [DEFAULT_GROUP];
/** Session-age window for the admin step-up; separate from Kratos's 5m privileged window. */
export const ADMIN_FRESHNESS_HOURS = 1;
/** Floor on CSRF_SECRET and RECOVERY_GATE_SECRET, by UTF-8 byte length (multi-byte characters would undercount entropy). */
export const SECRET_MIN_BYTES = 32;
