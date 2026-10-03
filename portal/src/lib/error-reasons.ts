// Reasons the /auth/error page knows how to describe. Plain household language: what happened, then what to do next.

export interface ErrorEntry {
  status: number;
  title: string;
  message: string;
}

export const REASON_MAP: Record<string, ErrorEntry> = {
  'not-admin': {
    status: 403,
    title: 'This page is for household admins',
    message: 'Your account can sign in but cannot manage the household. Ask an admin if you need something changed.',
  },
  'not-authorised': {
    status: 403,
    title: "You don't have access to that",
    message: 'Your account is not set up for it yet. Ask an admin to give you access, then try again.',
  },
  'auth-unreachable': {
    status: 503,
    title: 'Sign-in is taking a break',
    message: "We can't reach the sign-in service right now. Wait a minute and try again.",
  },
  'session-expired': {
    status: 401,
    title: 'Please sign in again',
    message: 'You were signed out to keep your account safe. Sign in to pick up where you left off.',
  },
  'forbidden': {
    status: 403,
    title: "You can't open that",
    message: 'Your account does not have permission for this page. Go home, or ask an admin for access.',
  },
  'unavailable': {
    status: 503,
    title: 'Back in a moment',
    message: 'Something this page needs is not responding. Wait a minute and try again.',
  },
  'not-found': {
    status: 404,
    title: "We can't find that page",
    message: 'It may have moved, or the link may be mistyped. Go home to find what you were after.',
  },
  'rate-limited': {
    status: 429,
    title: 'Too many tries',
    message: 'Please wait a minute, then try again.',
  },
  'flow-expired': {
    status: 410,
    title: 'That page timed out',
    message: 'Sign-in pages only last a few minutes. Go back to the app and choose sign in again, or start again here.',
  },
  'app-misconfigured': {
    status: 400,
    title: "This app isn't set up for sign-in",
    message: "The app sent a request we don't recognise. Ask your household admin to look at it, and tell them which app it was.",
  },
  'sign-in-cancelled': {
    status: 403,
    title: 'Sign-in was cancelled',
    message: 'The app was not allowed to sign you in. Go back to the app and choose sign in to try again.',
  },
  'server-error': {
    status: 500,
    title: 'Something went wrong on our side',
    message: 'It is not you. Try again in a moment, and tell an admin if it keeps happening.',
  },
};

export const DEFAULT_ENTRY: ErrorEntry = {
  status: 400,
  title: "That didn't work",
  message: 'Wait a minute and try again; tell an admin if it repeats.',
};

/** The entry for a reason. The reason token is not shown to people: it is a code, not a sentence. */
export function resolveReason(raw: string | null): { entry: ErrorEntry; reason?: string } {
  if (raw !== null && Object.hasOwn(REASON_MAP, raw)) return { entry: REASON_MAP[raw], reason: raw };
  return { entry: DEFAULT_ENTRY };
}

/** Hydra's OAuth2 `error` codes, by what the person should do next. */
const HYDRA_ERRORS: Record<string, string> = {
  invalid_client: 'app-misconfigured',
  unauthorized_client: 'app-misconfigured',
  invalid_request: 'app-misconfigured',
  invalid_scope: 'app-misconfigured',
  unsupported_response_type: 'app-misconfigured',
  access_denied: 'sign-in-cancelled',
  login_required: 'flow-expired',
  consent_required: 'flow-expired',
  interaction_required: 'flow-expired',
  request_unauthorized: 'flow-expired',
  server_error: 'unavailable',
  temporarily_unavailable: 'unavailable',
};

/** Kratos self-service error ids (GET /self-service/errors) and, failing an id, their HTTP codes. */
const KRATOS_ERRORS: Record<string, string> = {
  self_service_flow_expired: 'flow-expired',
  self_service_flow_replaced: 'flow-expired',
  security_csrf_violation: 'flow-expired',
  session_inactive: 'session-expired',
  session_refresh_required: 'session-expired',
  self_service_flow_return_to_forbidden: 'app-misconfigured',
};
const KRATOS_CODES: Record<number, string> = {
  410: 'flow-expired',
  403: 'flow-expired',
  500: 'unavailable',
  502: 'unavailable',
  503: 'unavailable',
  504: 'unavailable',
};

/** What a Kratos error body (id and HTTP code) means for the page, or undefined to show the generic entry. */
export function kratosReason(err: { id?: unknown; code?: unknown } | null | undefined): string | undefined {
  if (!err) return undefined;
  if (typeof err.id === 'string' && Object.hasOwn(KRATOS_ERRORS, err.id)) return KRATOS_ERRORS[err.id];
  return typeof err.code === 'number' && Object.hasOwn(KRATOS_CODES, err.code) ? KRATOS_CODES[err.code] : undefined;
}

/** The page's entry from its query: our own `reason`, a Hydra `error` (its description is never shown), or a Kratos error already looked up by `?id=`. */
export function resolveError(params: URLSearchParams, kratos?: string): { entry: ErrorEntry; reason?: string } {
  const own = params.get('reason');
  if (own !== null && Object.hasOwn(REASON_MAP, own)) return resolveReason(own);
  const hydra = params.get('error');
  if (hydra !== null && Object.hasOwn(HYDRA_ERRORS, hydra)) return resolveReason(HYDRA_ERRORS[hydra]);
  return kratos ? resolveReason(kratos) : resolveReason(null);
}
