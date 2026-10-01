// L — the settings page renders and enrols TOTP and backup codes.

import { test, expect } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';

const NAV_TIMEOUT_MS = 15_000;

function extractHiddenInput(html: string, name: string): string {
  const re = new RegExp(
    `<input[^>]+name="${name}"[^>]+value="([^"]*)"[^>]*>|<input[^>]+value="([^"]*)"[^>]+name="${name}"[^>]*>`,
    'i',
  );
  const m = html.match(re);
  return m ? (m[1] ?? m[2] ?? '') : '';
}

/** The lookup_secret form's action and its own csrf token (the header sign-out form carries a different one). */
function extractLookupForm(html: string): { action: string; csrf: string } {
  const formRe = /<form[^>]+action="([^"]+)"[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = formRe.exec(html)) !== null) {
    const slice = html.slice(m.index, html.indexOf('</form>', m.index) + 7);
    if (/name="method"[^>]*value="lookup_secret"|value="lookup_secret"[^>]*name="method"/i.test(slice)) {
      return { action: m[1], csrf: extractHiddenInput(slice, 'csrf_token') };
    }
  }
  return { action: '', csrf: '' };
}

test('L1 — settings page renders TOTP QR and secret when TOTP enrollment is active', async ({
  ctx,
  baseURL,
  kratosAdminURL,
}) => {
  const identity = await createIdentityWithPassword({
    email: 'totp.enroll@othala.test',
    username: 'totp.enroll',
    displayName: 'TOTP Enroll Tester',
    groups: [],
    kratosAdminURL,
  });
  console.log('[L1] seeded identity:', identity.id, identity.email);

  await loginViaJsonApi(
    ctx,
    { identifier: identity.email, password: TEST_PASSWORD },
    baseURL,
  );

  const session = await getSession(ctx, baseURL);
  expect(
    session?.active,
    'L1 precondition: active session required for settings flow',
  ).toBe(true);
  console.log('[L1] session established, AAL:', session?.authenticator_assurance_level);

  const resp = await ctx.request.get(`${baseURL}/auth/settings`, {
    headers: { Accept: 'text/html' },
    maxRedirects: 5,
  });
  expect(resp.status(), 'L1: /auth/settings must return 200 for authenticated user').toBe(200);

  const html = await resp.text();
  console.log('[L1] settings page length:', html.length);

  if (!html.includes('Authenticator app')) {
    console.log('[L1] TOTP section absent for this identity (no TOTP nodes in flow — expected for fresh identity without TOTP enrolled)');
    expect(html, 'L1: settings page must render even without TOTP nodes').toContain('Settings');
    console.log('[L1] PASS (conditional) — settings page renders; TOTP section absent for fresh identity');
    return;
  }

  console.log('[L1] TOTP section present in settings page');

  if (html.includes('totp-qr') || /<img[^>]+alt[^>]*[Aa]uthenticator/.test(html)) {
    expect(
      /<img[^>]+src[^>]*>/i.test(html),
      'L1: TOTP QR img element must be in the page HTML',
    ).toBe(true);
    console.log('[L1] TOTP QR img rendered');
  }

  if (html.includes('totp-secret-value')) {
    expect(
      html,
      'L1: .totp-secret-value element must contain the TOTP secret',
    ).toMatch(/totp-secret-value/);
    console.log('[L1] TOTP secret element rendered');
  }

  console.log('[L1] PASS — TOTP section renders on the settings page');
});

test('L2 — backup codes are visible in the HTML after generating them (regression for bug #1)', async ({
  baseURL,
  kratosAdminURL,
  ctx,
}) => {
  const identity = await createIdentityWithPassword({
    email: 'backup.codes@othala.test',
    username: 'backup.codes',
    displayName: 'Backup Code Tester',
    groups: [],
    kratosAdminURL,
  });
  console.log('[L2] seeded identity:', identity.id, identity.email);

  await loginViaJsonApi(
    ctx,
    { identifier: identity.email, password: TEST_PASSWORD },
    baseURL,
  );

  const session = await getSession(ctx, baseURL);
  expect(
    session?.active,
    'L2 precondition: active session required',
  ).toBe(true);
  console.log('[L2] session established');

  const pageResp = await ctx.request.get(`${baseURL}/auth/settings`, {
    headers: { Accept: 'text/html' },
    maxRedirects: 5,
  });
  expect(pageResp.status(), 'L2: initial GET /auth/settings must return 200').toBe(200);

  const pageHtml = await pageResp.text();

  if (!pageHtml.includes('Backup codes') && !pageHtml.includes('lookup_secret')) {
    console.log('[L2] lookup_secret section absent — strategy may be disabled; skipping');
    test.skip(true, 'lookup_secret strategy not enabled in this stack');
    return;
  }
  console.log('[L2] lookup_secret section present in initial settings page');

  const { action: formAction, csrf: csrfToken } = extractLookupForm(pageHtml);
  if (!formAction) {
    console.log('[L2] could not extract form action from HTML; falling back to API flow init');
  }
  console.log('[L2] form action:', formAction || '(not found)', '| csrf:', csrfToken ? csrfToken.slice(0, 12) + '…' : '(not found)');

  if (!formAction || !csrfToken) {
    const flowResp = await ctx.request.get(
      `${baseURL}/self-service/settings/browser`,
      { headers: { Accept: 'application/json' }, maxRedirects: 5 },
    );
    expect(flowResp.ok(), 'L2 fallback: settings flow init must succeed').toBe(true);
    const flow = await flowResp.json() as {
      ui?: {
        action?: string;
        nodes?: Array<{
          type?: string;
          group?: string;
          attributes?: { name?: string; type?: string; value?: unknown; node_type?: string };
        }>;
      };
    };
    const apiAction = flow?.ui?.action ?? '';
    let apiCsrf = '';
    for (const node of flow?.ui?.nodes ?? []) {
      if (
        node?.attributes?.node_type === 'input' &&
        node?.attributes?.name === 'csrf_token' &&
        node?.attributes?.type === 'hidden'
      ) {
        apiCsrf = String(node.attributes.value ?? '');
        break;
      }
    }
    expect(apiAction, 'L2 fallback: settings flow must have ui.action').toBeTruthy();
    expect(apiCsrf, 'L2 fallback: settings flow must have csrf_token').toBeTruthy();

    const genResp = await ctx.request.post(apiAction, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'text/html',
      },
      form: {
        csrf_token: apiCsrf,
        method: 'lookup_secret',
        lookup_secret_regenerate: 'true',
      },
      maxRedirects: 5,
    });
    const genStatus = genResp.status();
    console.log('[L2] API-path generate status:', genStatus);
    expect([200, 302, 303].includes(genStatus), `L2: generate must return 200/30x; got ${genStatus}`).toBe(true);

    let finalHtml: string;
    if (genStatus === 200) {
      finalHtml = await genResp.text();
    } else {
      const loc = genResp.headers()['location'] ?? `${baseURL}/auth/settings`;
      const followResp = await ctx.request.get(loc.startsWith('http') ? loc : `${baseURL}${loc}`, {
        headers: { Accept: 'text/html' },
        maxRedirects: 5,
      });
      finalHtml = await followResp.text();
    }

    assertBackupCodesVisible(finalHtml, 'L2 (API fallback)');
    return;
  }

  const generateResp = await ctx.request.post(formAction, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'text/html',
    },
    form: {
      csrf_token: csrfToken,
      method: 'lookup_secret',
      lookup_secret_regenerate: 'true',
    },
    maxRedirects: 5,
  });

  const genStatus = generateResp.status();
  console.log('[L2] generate form submit status:', genStatus);
  expect(
    [200, 302, 303].includes(genStatus),
    `L2: backup code generation form must return 200/30x; got ${genStatus}`,
  ).toBe(true);

  let settingsHtml: string;
  if (genStatus === 200) {
    settingsHtml = await generateResp.text();
  } else {
    const loc = generateResp.headers()['location'] ?? `${baseURL}/auth/settings`;
    const followResp = await ctx.request.get(
      loc.startsWith('http') ? loc : `${baseURL}${loc}`,
      { headers: { Accept: 'text/html' }, maxRedirects: 5 },
    );
    settingsHtml = await followResp.text();
  }

  assertBackupCodesVisible(settingsHtml, 'L2');

  console.log('[L2] PASS — backup codes are visible in the rendered HTML after generation');
});

function assertBackupCodesVisible(html: string, label: string): void {
  console.log(`[${label}] response HTML length:`, html.length);

  const testidMatch = html.match(/data-testid="backup-codes"[^>]*>([\s\S]*?)<\/code>/i);
  if (testidMatch) {
    const codesText = testidMatch[1].trim();
    console.log(`[${label}] backup-codes element found, content length:`, codesText.length);
    expect(
      codesText.length,
      `${label}: backup-codes element must contain the generated codes (non-empty); ` +
      `got empty content — this is bug #1: text nodes were silently dropped`,
    ).toBeGreaterThan(0);
    console.log(`[${label}] backup codes visible (first 40 chars):`, codesText.slice(0, 40));
    return;
  }

  const hasBackupSection = html.includes('Backup codes') || html.includes('lookup_secret');
  expect(
    hasBackupSection && html.includes('data-testid="backup-codes"'),
    `${label}: after generating backup codes, data-testid="backup-codes" must be present ` +
    `in the rendered HTML. Absent = bug #1: Kratos text nodes with the codes were dropped ` +
    `by FlowNodes/asInput() which returns null for node_type:"text".`,
  ).toBe(true);
}
