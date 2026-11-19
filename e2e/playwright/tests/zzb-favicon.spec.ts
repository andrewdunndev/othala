// ZZB — the mark's icons are served to a signed-out browser with an image type, and the login page links them.

import { test, expect } from '../fixtures';

const ICONS = ['/favicon.svg', '/favicon.ico', '/apple-touch-icon.png', '/icon-192.png', '/icon-512.png'];

test.describe('ZZB — favicon and manifest icons', () => {
  for (const path of ICONS) {
    test(`ZZB: ${path} is a signed-out image`, async ({ page, baseURL }) => {
      const resp = await page.context().request.get(`${baseURL}${path}`, { maxRedirects: 0 });
      expect(resp.status()).toBe(200);
      expect(resp.headers()['content-type'] ?? '').toMatch(/^image\//);
    });
  }

  test('ZZB: / links the icons', async ({ page, baseURL }) => {
    const html = await (await page.context().request.get(`${baseURL}/`)).text();
    expect(html).toMatch(/<link rel="icon" href="\/favicon\.svg" type="image\/svg\+xml"/);
    expect(html).toMatch(/<link rel="icon" href="\/favicon\.ico"/);
    expect(html).toMatch(/<link rel="apple-touch-icon" href="\/apple-touch-icon\.png"/);
  });
});
