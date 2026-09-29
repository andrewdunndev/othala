// Content-Security-Policy builder for the portal's response headers.
//
// form-action governs a form submission's whole redirect chain, not only its
// action URL. Two chains leave the portal origin:
//   - an OIDC login's post-login redirect lands on the requesting app, a
//     subdomain of the estate apex (https://*.<OTHALA_APEX>);
//   - sign-out POSTs to /auth/logout, which answers 303 to Kratos's logout_url.
//     That URL is on OTHALA_PUBLIC_URL (Kratos's base_url) or KRATOS_PUBLIC_URL,
//     the same two origins /auth/logout accepts, so both are listed here. Without
//     them, a Kratos on another host with OTHALA_APEX unset blocks sign-out.
// Unparseable or non-http(s) values contribute nothing.

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

export function formActionSources(opts: {
  apex?: string;
  kratosUrls: readonly (string | undefined)[];
}): string {
  const sources = ["'self'"];
  const apex = opts.apex?.trim();
  if (apex) sources.push(`https://*.${apex}`);
  for (const raw of opts.kratosUrls) {
    const origin = httpOrigin(raw);
    if (origin && !sources.includes(origin)) sources.push(origin);
  }
  return sources.join(' ');
}

export function contentSecurityPolicy(opts: {
  apex?: string;
  kratosUrls: readonly (string | undefined)[];
}): string {
  return `frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action ${formActionSources(opts)}`;
}
