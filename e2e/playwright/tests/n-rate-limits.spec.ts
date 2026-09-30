// N — abuse bursts are rate-limited at the proxy (MEDIUM-B).

import { test, expect } from '../fixtures';
import { MAILPIT_API } from '../actions/mail';

const CODE_REQUEST_BURST = 5;    // e2e_code_request zone: events 5
const WRONG_PASSWORD_BURST = 10; // e2e_wrong_password zone: events 10
const MAX_EMAILS_DELIVERED = CODE_REQUEST_BURST; // Mailpit delta cap

async function mailpitCount(ctx: import('@playwright/test').APIRequestContext): Promise<number | null> {
  const resp = await ctx.get(`${MAILPIT_API}/api/v1/messages`, { headers: { Accept: 'application/json' } });
  if (!resp.ok()) return null;
  const body = await resp.json() as { messages: unknown[]; total?: number };
  return body.total ?? body.messages?.length ?? 0;
}

test.describe('N — Abuse rate-limiting (gate-time, MEDIUM-B)', () => {
  test(
    'N1 — rapid code-requests return 429 before the burst limit (code-request flood)',
    async ({ page, baseURL }) => {
      const ctx = page.context();
      let got429 = false;

      const before = await mailpitCount(ctx.request);

      for (let i = 0; i < CODE_REQUEST_BURST + 2; i++) {
        const resp = await ctx.request.get(`${baseURL}/self-service/login/browser`, {
          headers: { Accept: 'application/json', 'X-E2E-Flood-Probe': 'n1' },
          maxRedirects: 0,
        });
        if (resp.status() === 429) {
          got429 = true;
          console.log(`[N1] 429 received at attempt ${i + 1}`);
          break;
        }
      }

      expect(
        got429,
        `N1: expected a 429 within ${CODE_REQUEST_BURST + 2} rapid requests, but none received. ` +
        'Rate-limiting is not configured (MEDIUM-B).',
      ).toBe(true);

      const after = await mailpitCount(ctx.request);
      if (before !== null && after !== null) {
        const delta = after - before;
        expect(
          delta,
          `N1: Mailpit grew by ${delta} messages during the flood; expected ≤ ${MAX_EMAILS_DELIVERED} ` +
          '(email amplification must be bounded by rate-limit)',
        ).toBeLessThanOrEqual(MAX_EMAILS_DELIVERED);
      } else {
        console.warn('[N1] Mailpit not reachable — email count check skipped');
      }
    },
  );

  test(
    'N2 — rapid wrong-password attempts return 429 before the burst limit (brute-force throttle)',
    async ({ page, baseURL }) => {
      const ctx = page.context();

      type LoginBrowserFlow = {
        ui?: {
          action?: string;
          nodes?: Array<{
            type?: string;
            attributes?: { name?: string; type?: string; value?: unknown };
          }>;
        };
      };
      let action = '';
      let csrfToken = '';
      let lastFlow: LoginBrowserFlow | null = null;
      for (let attempt = 1; attempt <= 3; attempt++) {
        const flowResp = await ctx.request.get(`${baseURL}/self-service/login/browser`, {
          headers: { Accept: 'application/json' },
          maxRedirects: 5,
        });
        expect(flowResp.ok(), `N2: login flow init must succeed (attempt ${attempt}/3)`).toBe(true);
        const flow = await flowResp.json() as LoginBrowserFlow;
        lastFlow = flow;
        action = flow?.ui?.action ?? '';
        for (const node of flow?.ui?.nodes ?? []) {
          if (node?.attributes?.name === 'csrf_token' && node?.attributes?.type === 'hidden') {
            csrfToken = String(node.attributes.value ?? '');
            break;
          }
        }
        if (action) break;
        console.log(`[N2] attempt ${attempt}/3: ui.action missing from flow response, retrying...`);
        await new Promise((r) => setTimeout(r, 300 * attempt));
      }

      expect(
        action,
        'N2: login flow ui.action missing after 3 attempts — a stack-readiness bug, not a legitimate ' +
        `skip reason; last flow: ${JSON.stringify(lastFlow).slice(0, 400)}`,
      ).toBeTruthy();

      let got429 = false;
      for (let i = 0; i < WRONG_PASSWORD_BURST + 2; i++) {
        const submitResp = await ctx.request.post(action, {
          headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'X-E2E-Flood-Probe': 'n2' },
          data: {
            identifier: 'nobody@othala.test',
            password: `wrong-password-${i}`,
            method: 'password',
            csrf_token: csrfToken,
          },
          maxRedirects: 0,
        });
        if (submitResp.status() === 429) {
          got429 = true;
          console.log(`[N2] 429 received at attempt ${i + 1}`);
          break;
        }
      }

      expect(
        got429,
        `N2: expected a 429 within ${WRONG_PASSWORD_BURST + 2} wrong-password attempts, but none received. ` +
        'Brute-force throttle is not configured (MEDIUM-B).',
      ).toBe(true);
    },
  );

  test(
    'N3 — buckets key on the client address: distinct addresses are separate',
    async ({ page, baseURL }) => {
      const ctx = page.context();
      const probe = (xff: string) =>
        ctx.request.get(`${baseURL}/self-service/login/browser`, {
          headers: { Accept: 'application/json', 'X-E2E-Flood-Probe': 'n1', 'X-Forwarded-For': xff },
          maxRedirects: 0,
        }).then((r) => r.status());

      const exhaust = async (xff: string) => {
        for (let i = 0; i < CODE_REQUEST_BURST + 2; i++) if ((await probe(xff)) === 429) return true;
        return false;
      };

      expect(await exhaust('203.0.113.1'), 'N3: first client must reach 429').toBe(true);
      expect(await probe('203.0.113.2'), 'N3: a different IPv4 client must have its own bucket').not.toBe(429);
    },
  );
});
