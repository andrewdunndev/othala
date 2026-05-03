// Minimal Kratos public-API client used by Astro pages.
//
// All calls go to `${KRATOS_PUBLIC_URL}/...` with `credentials: include`
// so the session cookie (domain=.dunn.dev) is attached.

const KRATOS = import.meta.env.PUBLIC_KRATOS_URL ?? 'https://auth.dunn.dev';

export interface Identity {
  id: string;
  traits: {
    username: string;
    email: string;
    displayName?: string;
    recoveryEmail?: string;
  };
  metadata_admin?: {
    groups?: string[];
  };
  verifiable_addresses?: Array<{
    value: string;
    verified: boolean;
    via: string;
  }>;
}

export interface Session {
  active: boolean;
  expires_at: string;
  authenticated_at: string;
  authenticator_assurance_level: 'aal0' | 'aal1' | 'aal2' | 'aal3';
  identity?: Identity;
}

export interface LoginFlow {
  id: string;
  type: 'browser' | 'api';
  expires_at: string;
  ui: FlowUI;
}

export interface FlowUI {
  action: string;
  method: string;
  nodes: FlowNode[];
  messages?: FlowMessage[];
}

export interface FlowNode {
  type: string;
  group: string;
  attributes: Record<string, unknown>;
  meta?: { label?: { text?: string } };
}

export interface FlowMessage {
  id: number;
  text: string;
  type: 'info' | 'error' | 'success';
}

/**
 * Get the user's current session. Returns null if not authenticated.
 *
 * Used by:
 *   - index.astro (state determination)
 *   - admin/* pages (session + AAL2 check)
 *   - the home portal post-auth render
 */
export async function whoami(cookieHeader?: string): Promise<Session | null> {
  const headers: Record<string, string> = {
    Accept: 'application/json',
  };
  if (cookieHeader) headers['Cookie'] = cookieHeader;

  const res = await fetch(`${KRATOS}/sessions/whoami`, {
    headers,
    credentials: 'include',
  });
  if (res.status === 401 || res.status === 403) return null;
  if (!res.ok) throw new Error(`whoami failed: ${res.status}`);
  return await res.json() as Session;
}

/**
 * Initiate a browser login flow. Returns a redirect URL the page should
 * navigate to (or the flow object if we want to drive UI inline).
 *
 * For our SPA-ish login page, we use the API flow:
 *   POST /self-service/login/api → flow object
 *
 * The page then renders form/WebAuthn challenge from flow.ui.nodes,
 * submits user input via POST /self-service/login?flow=<id>.
 */
export async function startLoginFlow(opts: {
  refresh?: boolean;
  aal?: 'aal1' | 'aal2';
  returnTo?: string;
} = {}): Promise<LoginFlow> {
  const params = new URLSearchParams();
  if (opts.refresh) params.set('refresh', 'true');
  if (opts.aal) params.set('aal', opts.aal);
  if (opts.returnTo) params.set('return_to', opts.returnTo);

  const url = `${KRATOS}/self-service/login/browser?${params.toString()}`;
  // Browser flow: navigate the user. API flow: fetch JSON.
  // For the SPA login page we use API flow:
  const res = await fetch(`${KRATOS}/self-service/login/api?${params.toString()}`, {
    headers: { Accept: 'application/json' },
    credentials: 'include',
  });
  if (!res.ok) throw new Error(`startLoginFlow failed: ${res.status}`);
  return await res.json() as LoginFlow;
}

/**
 * Submit the login flow. Body shape depends on chosen method
 * (password, webauthn, etc.).
 */
export async function submitLoginFlow(
  flowId: string,
  body: Record<string, unknown>,
): Promise<unknown> {
  const res = await fetch(`${KRATOS}/self-service/login?flow=${encodeURIComponent(flowId)}`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    credentials: 'include',
    body: JSON.stringify(body),
  });
  return await res.json();
}

// Recovery, settings, verification flows follow the same shape — add
// helpers as the corresponding pages are implemented.
