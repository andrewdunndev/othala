/**
 * Failure-path capture (screenshot, DOM, console) for the passkey login-trigger flake,
 * written under the /out bind mount. Best-effort: a capture failure never masks the test failure.
 */

import type { Page } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';

const OUT_DIR = process.env.DIAGNOSTICS_DIR ?? '/out/diagnostics';

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
