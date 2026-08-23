/**
 * O — Rendered anonymous login journey (work item #9 discriminator).
 *
 * 20 of 21 e2e specs authenticate through the Kratos JSON-API bypass
 * (actions/login.ts) and never render login.astro at all. v0.5.0 shipped an
 * EMPTY anonymous login page through that fully green suite — login.astro's
 * isAal2 derivation miscounted the always-present webauthn glue-script node
 * as a second factor, hiding every primary tier behind an empty step-up
 * card — because nothing in the suite ever loaded the page a real visitor
 * sees. This spec is that missing check: a real page.goto('/auth/login'),
 * hard assertions on the rendered DOM, zero test.skip, zero soft-exits, no
 * reliance on networkidle. It must go RED against the v0.5.0 image (#9's
 * mutation-probe acceptance criterion) and stay red on any regression of
 * the same class.
 *
 * Flow init: no ?flow= in the URL — login.astro's own redirect chain
 * (Astro.redirect(browserFlows.login()) -> Kratos sets the flow and
 * redirects back to /auth/login?flow=<id>) fires exactly as a fresh
 * anonymous visitor's browser would trigger it (same natural-redirect
 * entrypoint s-aal2-natural-redirect.spec.ts uses for the AAL2 side).
 */

import { test, expect } from '../fixtures';

test.describe('O — Rendered anonymous login journey', () => {
  test('O1 — anonymous AAL1 login page renders all three tiers, no AAL2 shell', async ({ page, baseURL }) => {
    await page.goto(`${baseURL}/auth/login`);

    expect(page.url(), 'O1: must land on the rendered login page with a live flow id').toMatch(/\/auth\/login\?.*flow=/);

    // Tier 1 — passkey. login.astro renders button[name="passkey_login_trigger"]
    // (Kratos passkey_login.go PasskeyLoginTrigger) with onclick wired to
    // window.oryPasskeyLogin by the bottom-of-page webauthn.js script node.
    const passkeyBtn = page.locator('button[name="passkey_login_trigger"]');
    await expect(passkeyBtn, 'O1: passkey login trigger must render').toBeVisible({ timeout: 15_000 });
    await page.waitForFunction(
      () => typeof (window as unknown as Record<string, unknown>).oryPasskeyLogin === 'function',
      undefined,
      { timeout: 15_000 },
    );

    // Tier 2 — email code. Identifier-step form (login.astro code-block,
    // isCodeEntry=false): email input + "Send sign-in code" submit.
    await expect(page.locator('#code-identifier'), 'O1: email-code identifier input must render').toBeVisible();
    await expect(
      page.locator('.code-form button.code-submit'),
      'O1: "Send sign-in code" submit must render',
    ).toBeVisible();

    // Tier 3 — password (collapsed <details> disclosure). Content inside a
    // closed <details> isn't "visible" per the UA stylesheet — assert the
    // summary affordance is visible AND the form fields are attached to the
    // DOM, not merely that the disclosure element exists.
    await expect(
      page.locator('.password-summary-label', { hasText: /use a password/i }),
      'O1: password disclosure summary must render',
    ).toBeVisible();
    await expect(page.locator('#pw-identifier'), 'O1: password-tier username input must be in the DOM').toBeAttached();
    await expect(page.locator('#password'), 'O1: password-tier password input must be in the DOM').toBeAttached();

    // No AAL2 step-up shell — an anonymous first visit is AAL1; login.astro
    // renders .aal2-block only when isAal2 (requested_aal:'aal2' or a real
    // second-factor node present). Its presence here IS the v0.5.0 bug shape
    // (primary tiers hidden behind an empty step-up card).
    await expect(page.locator('.aal2-block'), 'O1: no AAL2 step-up shell on an anonymous AAL1 visit').toHaveCount(0);
  });
});
