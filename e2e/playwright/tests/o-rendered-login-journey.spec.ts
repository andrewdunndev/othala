// O — the rendered anonymous login journey works without the JSON-API bypass.

import { test, expect } from '../fixtures';

test.describe('O — Rendered anonymous login journey', () => {
  test('O1 — anonymous AAL1 login page renders all three tiers, no AAL2 shell', async ({ page, baseURL }) => {
    await page.goto(`${baseURL}/auth/login`);

    expect(page.url(), 'O1: must land on the rendered login page with a live flow id').toMatch(/\/auth\/login\?.*flow=/);

    const passkeyBtn = page.locator('button[name="passkey_login_trigger"]');
    await expect(passkeyBtn, 'O1: passkey login trigger must render').toBeVisible({ timeout: 15_000 });
    await page.waitForFunction(
      () => typeof (window as unknown as Record<string, unknown>).oryPasskeyLogin === 'function',
      undefined,
      { timeout: 15_000 },
    );

    await expect(page.locator('#code-identifier'), 'O1: email-code identifier input must render').toBeVisible();
    await expect(
      page.locator('.code-form button.code-submit'),
      'O1: "Send sign-in code" submit must render',
    ).toBeVisible();

    await expect(
      page.locator('.password-summary-label', { hasText: /use a password/i }),
      'O1: password disclosure summary must render',
    ).toBeVisible();
    await expect(page.locator('#pw-identifier'), 'O1: password-tier username input must be in the DOM').toBeAttached();
    await expect(page.locator('#password'), 'O1: password-tier password input must be in the DOM').toBeAttached();

    await expect(page.locator('.aal2-block'), 'O1: no AAL2 step-up shell on an anonymous AAL1 visit').toHaveCount(0);

    const firstStop = await page.evaluate(() => document.querySelector('a[href], button, input, select, textarea')?.textContent?.trim());
    expect(firstStop, 'O1: the skip link is the first focusable element').toBe('Skip to content');
  });
});
