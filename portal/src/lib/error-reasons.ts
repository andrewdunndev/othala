// Reasons the /auth/error page knows how to describe.

export interface ErrorEntry {
  status: number;
  title: string;
  message: string;
}

export const REASON_MAP: Record<string, ErrorEntry> = {
  'not-admin': {
    status: 403,
    title: 'Not authorised',
    message:
      'Your account does not have administrator access. If you believe this is incorrect, contact your administrator.',
  },
  'not-authorised': {
    status: 403,
    title: 'Not authorised',
    message:
      'Your account does not have access to this resource. Contact your administrator to request access.',
  },
  'auth-unreachable': {
    status: 503,
    title: 'Auth temporarily unavailable',
    message:
      'The authentication service is temporarily unreachable. Please try again in a moment.',
  },
  'session-expired': {
    status: 401,
    title: 'Session expired',
    message: 'Your session has expired or is no longer valid. Please sign in again.',
  },
  'forbidden': {
    status: 403,
    title: 'Forbidden',
    message: 'You do not have permission to access this resource.',
  },
  'unavailable': {
    status: 503,
    title: 'Service temporarily unavailable',
    message: 'A dependency is temporarily unavailable. Please try again in a moment.',
  },
  'not-found': {
    status: 404,
    title: 'Not found',
    message: 'The page you are looking for does not exist or has moved.',
  },
  'rate-limited': {
    status: 429,
    title: 'Too many requests',
    message: 'You have made too many requests. Please wait a moment and try again.',
  },
  'server-error': {
    status: 500,
    title: 'Something went wrong',
    message: 'An unexpected error occurred. Please try again in a moment.',
  },
};

export const DEFAULT_ENTRY: ErrorEntry = {
  status: 400,
  title: 'Access denied',
  message: 'Your request could not be completed. Please sign in and try again.',
};

/** The entry for a reason, and the reason text to show: only a known key is shown. */
export function resolveReason(raw: string | null): { entry: ErrorEntry; reason?: string } {
  if (raw !== null && Object.hasOwn(REASON_MAP, raw)) return { entry: REASON_MAP[raw], reason: raw };
  return { entry: DEFAULT_ENTRY };
}
