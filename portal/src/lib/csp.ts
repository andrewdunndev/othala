// Content-Security-Policy builder. form-action covers a form's whole redirect
// chain: an OIDC login lands on a subdomain of the apex (https://*.<OTHALA_APEX>),
// and sign-out 303s to Kratos's logout_url on OTHALA_PUBLIC_URL or
// KRATOS_PUBLIC_URL, the two origins /auth/logout accepts. Unparseable or
// non-http(s) values contribute nothing.

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
