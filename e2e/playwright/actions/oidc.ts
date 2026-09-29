import type { BrowserContext } from 'playwright-core';

/**
 * Follow redirects by hand from `start` until `stop(location)` holds or no
 * Location is returned. Returns every Location seen, in order.
 */
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
