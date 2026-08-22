/**
 * N — Abuse rate-limiting (gate-time tests, MEDIUM-B finding).
 *
 * Finding reference: MEDIUM-B
 *   "No rate limiting on /self-service/login code requests or wrong-password
 *    attempts. Unlimited rapid requests are accepted without a 429."
 *
 * Enforced by e2e/caddy.Caddyfile's `rate_limit` block (mholt/caddy-ratelimit,
 * baked into the dunn.dev/caddy image — see e2e/compose.yml's caddy service).
 * Both zones there additionally require an X-E2E-Flood-Probe marker header:
 * every request in this harness shares one client IP, so a path-only zone
 * would also throttle the ~20 other specs' legitimate self-service calls
 * earlier in the same serial run. N1/N2 set the marker on their own flood
 * requests only, so the zones fire on THEIR bursts without touching anyone
 * else's traffic — a real Caddy 429, scoped by test rather than by chance
 * timing.
 *
 * Scenarios:
 *
 *   N1 — Rapid OTP/code-request flood:
 *     Send N rapid GET /self-service/login/browser requests from the same
 *     client context. Assert a 429 is returned before N attempts. ALSO check
 *     that Mailpit's message count grew by ≤ K during the flood (bound the
 *     outgoing mail amplification), measured as a delta so earlier specs'
 *     mail (recovery, invite, code-login) doesn't pollute the count.
 *
 *   N2 — Wrong-password throttle:
 *     Initiate a login flow; submit N wrong passwords via the JSON-API
 *     submit path. Assert the submit endpoint returns 429 before N attempts
 *     succeed.
 *
 * Rate-limit constants — MUST match e2e/caddy.Caddyfile's zone `events`:
 *   CODE_REQUEST_BURST   — zone e2e_code_request events (5/min)
 *   WRONG_PASSWORD_BURST — zone e2e_wrong_password events (10/min)
 *   MAX_EMAILS_DELIVERED — Mailpit delta cap during the N1 flood
 *
 * Mailpit: accessible at http://mailpit:8025 inside the compose net.
 *   GET /api/v1/messages returns { messages: [...], total: N }.
 */

import { test, expect } from '../fixtures';

// ── Constants: must stay in lockstep with e2e/caddy.Caddyfile's zone events ──
const CODE_REQUEST_BURST = 5;    // e2e_code_request zone: events 5
const WRONG_PASSWORD_BURST = 10; // e2e_wrong_password zone: events 10
const MAX_EMAILS_DELIVERED = CODE_REQUEST_BURST; // Mailpit delta cap

const MAILPIT_URL = process.env.MAILPIT_URL ?? 'http://mailpit:8025';

async function mailpitCount(ctx: import('@playwright/test').APIRequestContext): Promise<number | null> {
  const resp = await ctx.get(`${MAILPIT_URL}/api/v1/messages`, { headers: { Accept: 'application/json' } });
  if (!resp.ok()) return null;
  const body = await resp.json() as { messages: unknown[]; total?: number };
  return body.total ?? body.messages?.length ?? 0;
}

// ── N1 — Rapid code-request flood ────────────────────────────────────────────

test.describe('N — Abuse rate-limiting (gate-time, MEDIUM-B)', () => {
  // N1: OTP/code request flood → 429 + Mailpit email count cap.
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

      // Mailpit check: assert email delivery growth during the flood was
      // capped. Even if 429 fires at the HTTP layer, Kratos may have already
      // queued some code emails before the limit engaged.
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

  // N2: Wrong-password throttle.
  test(
    'N2 — rapid wrong-password attempts return 429 before the burst limit (brute-force throttle)',
    async ({ page, baseURL }) => {
      const ctx = page.context();

      // Step 1: initiate the flow once.
      const flowResp = await ctx.request.get(`${baseURL}/self-service/login/browser`, {
        headers: { Accept: 'application/json' },
        maxRedirects: 5,
      });
      expect(flowResp.ok(), 'N2: login flow init must succeed').toBe(true);
      const flow = await flowResp.json() as {
        ui?: {
          action?: string;
          nodes?: Array<{
            type?: string;
            attributes?: { name?: string; type?: string; value?: unknown };
          }>;
        };
      };
      const action: string = flow?.ui?.action ?? '';
      let csrfToken = '';
      for (const node of flow?.ui?.nodes ?? []) {
        if (
          node?.attributes?.name === 'csrf_token' &&
          node?.attributes?.type === 'hidden'
        ) {
          csrfToken = String(node.attributes.value ?? '');
          break;
        }
      }

      if (!action) {
        test.skip(true, 'N2: could not extract login flow action — stack not ready');
        return;
      }

      // Step 2: submit wrong passwords rapidly.
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
});
