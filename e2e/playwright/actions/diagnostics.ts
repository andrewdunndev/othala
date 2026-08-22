/**
 * diagnostics.ts — failure-path capture for the passkey login-trigger flake
 * (I1 / P2: `button[name="passkey_login_trigger"]` sometimes absent from
 * /auth/login). Writes to /out/diagnostics, a sibling of playwright.config.ts's
 * outputDir/html-report under the SAME /out bind mount (browser-out on the
 * host), so a CI artifact pull gets it alongside the html report.
 *
 * Three artifacts per call, all best-effort (a capture failure must never
 * mask the real test failure):
 *   - <label>-screenshot.png  — what the page actually rendered
 *   - <label>-dom.html        — server-rendered HTML (proves/disproves a
 *                               portal-side omission vs a client-side one)
 *   - <label>-flow.json       — the live login flow re-fetched from Kratos's
 *                               public API by the ?flow= id in the URL
 *                               (same call login.astro makes server-side) —
 *                               the authoritative answer to "did Kratos's
 *                               ui.nodes include a passkey group node".
 */

import type { Page } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';

const OUT_DIR = process.env.DIAGNOSTICS_DIR ?? '/out/diagnostics';

/**
 * probePasskeyLoginCapabilities — reads the browser's own WebAuthn capability
 * signals right after a /auth/login load, for the login-trigger flake
 * (button[name="passkey_login_trigger"] sometimes absent). Distinguishes a
 * client-capability gate (conditionalMediationAvailable false, no ory*
 * globals) from a server-side omission (probe looks fine, button still
 * missing — see capturePasskeyLoginDiagnostics's flow.json fetch for that case).
 */
export async function probePasskeyLoginCapabilities(page: Page): Promise<Record<string, unknown>> {
  return page.evaluate(async () => {
    const w = window as unknown as Record<string, unknown>;
    let conditional: unknown;
    try {
      conditional = await (
        window as unknown as { PublicKeyCredential?: { isConditionalMediationAvailable?: () => Promise<boolean> } }
      ).PublicKeyCredential?.isConditionalMediationAvailable?.();
    } catch (e) {
      conditional = `error: ${e}`;
    }
    return {
      hasPublicKeyCredential: typeof (w as { PublicKeyCredential?: unknown }).PublicKeyCredential !== 'undefined',
      conditionalMediationAvailable: conditional,
      oryPasskeyLoginDefined: typeof w.oryPasskeyLogin === 'function',
      oryGlobals: Object.keys(w).filter((k) => k.startsWith('ory')),
    };
  });
}

export async function capturePasskeyLoginDiagnostics(page: Page, label: string): Promise<void> {
  try {
    mkdirSync(OUT_DIR, { recursive: true });
  } catch {
    return; // no writable output dir (e.g. local run outside compose) — skip silently
  }

  await page.screenshot({ path: `${OUT_DIR}/${label}-screenshot.png`, fullPage: true }).catch((e) => {
    console.log(`[diagnostics] screenshot failed: ${e}`);
  });

  await page
    .content()
    .then((html) => writeFileSync(`${OUT_DIR}/${label}-dom.html`, html))
    .catch((e) => console.log(`[diagnostics] page.content() failed: ${e}`));

  const flowId = new URL(page.url()).searchParams.get('flow');
  if (!flowId) {
    console.log(`[diagnostics] ${label}: no ?flow= in URL (${page.url()}) — skipping flow fetch`);
    return;
  }
  // In-page fetch (not ctx.request): same-origin credentials are sent
  // automatically, matching exactly what the browser itself would send.
  const flow = await page
    .evaluate(async (id) => {
      const r = await fetch(`/self-service/login/flows?id=${id}`, { headers: { Accept: 'application/json' } });
      return { status: r.status, body: await r.text() };
    }, flowId)
    .catch((e) => ({ status: 0, body: String(e) }));
  writeFileSync(`${OUT_DIR}/${label}-flow.json`, flow.body);
  const hasPasskeyGroup = flow.body.includes('"group":"passkey"');
  console.log(
    `[diagnostics] ${label}: flow ${flowId} fetch status=${flow.status}, ` +
    `ui.nodes has a passkey group node: ${hasPasskeyGroup}`,
  );
}
