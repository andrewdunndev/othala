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
  'server-error': {
    status: 500,
    title: 'Something went wrong on our side',
    message: 'It is not you. Try again in a moment, and tell an admin if it keeps happening.',
  },
};

export const DEFAULT_ENTRY: ErrorEntry = {
  status: 400,
  title: "That didn't work",
  message: 'Your request could not be completed. Sign in again and try once more.',
};

/** The entry for a reason. The reason token is not shown to people: it is a code, not a sentence. */
export function resolveReason(raw: string | null): { entry: ErrorEntry; reason?: string } {
  if (raw !== null && Object.hasOwn(REASON_MAP, raw)) return { entry: REASON_MAP[raw], reason: raw };
  return { entry: DEFAULT_ENTRY };
}
