import type { BrowserContext } from 'playwright-core';

/** Follow redirects by hand until stop(location) holds; returns every Location seen. */
export async function walk(ctx: BrowserContext, baseURL: string, start: string, stop: (loc: URL) => boolean): Promise<URL[]> {
  const seen: URL[] = [];
  let url = start;
  for (let hop = 0; hop < 12; hop++) {
    const resp = await ctx.request.get(url, { maxRedirects: 0 });
    const loc = resp.headers()['location'];
    if (!loc) return seen;
    const parsed = new URL(loc, url.startsWith('http') ? url : baseURL);
    seen.push(parsed);
    if (stop(parsed)) return seen;
    url = parsed.toString();
  }
  throw new Error(`redirect chain did not settle in 12 hops (last: ${url})`);
}

/** The named environment variable; throws when it is unset or empty. */
export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set; inject it from the compose environment`);
  return value;
}
