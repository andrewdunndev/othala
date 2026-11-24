// Content-Security-Policy builder. form-action covers a form's whole redirect
// chain: an OIDC login lands on a subdomain of the apex (https://*.<OTHALA_APEX>),
// and sign-out 303s to Kratos's logout_url on OTHALA_PUBLIC_URL or
// the internal Kratos address, the two origins /auth/logout accepts. A native app's
// redirect_uri (app.example:///callback) ends a sign-in POST's chain on its own
// scheme, so each such scheme registered in the loaded client manifests is allowed
// as a scheme-source; without it the browser blocks the last hop and the app never
// gets its code. Unparseable values, http(s) and script- or document-bearing schemes
// contribute nothing.

const SCHEME_RE = /^([a-z][a-z0-9+.-]*):/i;
// Never a scheme-source: http(s) would widen the origin list to every host; the rest load or run content.
const REFUSED_SCHEMES = new Set(['http', 'https', 'javascript', 'data', 'blob', 'filesystem', 'about', 'file', 'vbscript', 'ws', 'wss']);

function httpOrigin(raw: string | undefined): string | null {
  if (!raw) return null;
  try {
    const url = new URL(raw.trim());
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    return url.origin;
  } catch {
    return null;
  }
}

/** The `scheme:` source of a native-app redirect_uri, or null for http(s), refused or malformed values. */
export function redirectSchemeSource(raw: string | undefined): string | null {
  const scheme = SCHEME_RE.exec(raw?.trim() ?? '')?.[1]?.toLowerCase();
  if (!scheme || REFUSED_SCHEMES.has(scheme)) return null;
  return `${scheme}:`;
}

export function formActionSources(opts: {
  apex?: string;
  kratosUrls: readonly (string | undefined)[];
  redirectUris?: readonly (string | undefined)[];
}): string {
  const sources = ["'self'"];
  const apex = opts.apex?.trim();
  if (apex) sources.push(`https://*.${apex}`);
  for (const raw of opts.kratosUrls) {
    const origin = httpOrigin(raw);
    if (origin && !sources.includes(origin)) sources.push(origin);
  }
  for (const raw of opts.redirectUris ?? []) {
    const scheme = redirectSchemeSource(raw);
    if (scheme && !sources.includes(scheme)) sources.push(scheme);
  }
  return sources.join(' ');
}

export function contentSecurityPolicy(opts: {
  apex?: string;
  kratosUrls: readonly (string | undefined)[];
  redirectUris?: readonly (string | undefined)[];
}): string {
  return `frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action ${formActionSources(opts)}`;
}
