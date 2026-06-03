/**
 * A — Login → session (browser-test.mjs assertion A).
 *
 * A real Kratos session is established via the JSON-API login action (NOT
 * DOM scraping). After login, GET /sessions/whoami confirms the session is
 * active and tied to the correct identity (bt2@othala.test).
 *
 * Why JSON-API login instead of form scraping:
 *   The rendered login widget has a CSS transition:0.6s on inputs that makes
 *   Playwright actionability checks time out (finding from browser-test.mjs).
 *   The JSON-API path bypasses the widget while still flowing through Caddy →
 *   Kratos, so the resulting session cookie is domain-bound to othala.test
 *   exactly as a normal human form submit would produce.
 */

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';

test('A — member login establishes a real Kratos session', async ({
  browser,
  baseURL,
  member,
}) => {
  // Fresh browser context: clean cookie jar, no prior session.
  const ctx = await browser.newContext();

  try {
    // Execute the JSON-API Kratos login for the member identity.
    const sessionCookie = await loginViaJsonApi(
      ctx,
      { identifier: member.email, password: member.password },
      baseURL,
    );
    console.log('[A] session cookie set:', sessionCookie !== '(no session cookie found)');

    // Probe /sessions/whoami — must be 200/active with the correct email.
    const whoami = await getSession(ctx, baseURL);

    expect(whoami).not.toBeNull();
    expect(whoami!.active).toBe(true);
    expect(whoami!.identity?.traits?.email).toBe(member.email);
  } finally {
    await ctx.close();
  }
});
