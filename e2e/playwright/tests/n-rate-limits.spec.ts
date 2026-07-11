/**
 * N — Abuse rate-limiting (gate-time tests, MEDIUM-B finding).
 *
 * Finding reference: MEDIUM-B
 *   "No rate limiting on /self-service/login code requests or wrong-password
 *    attempts. Unlimited rapid requests are accepted without a 429."
 *
 * All tests in this file are marked test.fixme(): they FAIL on the current
 * stack (rate-limiting is not yet implemented at the Kratos/Caddy layer)
 * and should be UNFIXED until the rate-limit config lands.
 *
 * Gate-time intent:
 *   Un-fixme these tests when the rate-limit is configured. They then become
 *   the pass/fail gate for MEDIUM-B on the e2e run.
 *
 * Scenarios:
 *
 *   N1 — Rapid OTP/code-request flood:
 *     Send N rapid GET /self-service/login/browser requests (or the code
 *     initiation endpoint) from the same client context. Assert a 429 is
 *     returned before N attempts. ALSO check that Mailpit received ≤ K
 *     delivered emails (bound the outgoing mail amplification).
 *
 *   N2 — Wrong-password throttle:
 *     Initiate a login flow; submit N wrong passwords via the JSON-API
 *     submit path. Assert the submit endpoint returns 429 (or Kratos
 *     rate-limited error) before N attempts succeed.
 *
 * Rate-limit constants (TUNE to match the deployed config):
 *   CODE_REQUEST_BURST — max code requests before 429 (target: ≤ 5/min)
 *   WRONG_PASSWORD_BURST — max wrong-password attempts before throttle (target: ≤ 10/min)
 *   MAX_EMAILS_DELIVERED — Mailpit should show ≤ this many messages after the flood
 *
 * Mailpit: accessible at http://mailpit:8025 inside the compose net.
 *   GET /api/v1/messages returns { messages: [...], count: N }.
 *
 * Live-stack requirements:
 *   - Rate-limiting configured in Caddy or Kratos (MEDIUM-B fix).
 *   - Mailpit compose service running (compose `browser` profile).
 *   - Playwright container on the compose net.
 */

import { test, expect } from '../fixtures';

// ── Constants: tune to match the deployed rate-limit config ──────────────────
// These numbers must be kept in sync with the deployed Caddy/Kratos limits.
const CODE_REQUEST_BURST = 5;    // expected max before 429 on code requests
const WRONG_PASSWORD_BURST = 10; // expected max before 429 on wrong passwords
const MAX_EMAILS_DELIVERED = CODE_REQUEST_BURST; // Mailpit cap

const MAILPIT_URL = process.env.MAILPIT_URL ?? 'http://mailpit:8025';

// ── N1 — Rapid code-request flood ────────────────────────────────────────────

test.describe('N — Abuse rate-limiting (gate-time, MEDIUM-B)', () => {
  // N1: OTP/code request flood → 429 + Mailpit email count cap.
  test.fixme(
    'N1 — rapid code-requests return 429 before the burst limit (code-request flood)',
    async ({ page, baseURL }) => {
      // TODO(MEDIUM-B): configure Caddy
      // rate_limit or Kratos ratelimit to cap code-request initiations.
      //
      // Implementation sketch:
      //   Send CODE_REQUEST_BURST + 2 rapid requests to initiate a code-based
      //   login flow. The endpoint is /self-service/login/browser (with
      //   refresh=true or via the code method endpoint). Assert a 429 is
      //   received at or before CODE_REQUEST_BURST + 1.
      const ctx = page.context();
      let got429 = false;

      for (let i = 0; i < CODE_REQUEST_BURST + 2; i++) {
        const resp = await ctx.request.get(`${baseURL}/self-service/login/browser`, {
          headers: { Accept: 'application/json' },
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

      // Mailpit check: assert that email delivery was capped.
      // Even if 429 fires at the HTTP layer, Kratos may have already queued
      // some code emails. The cap ensures the SMTP relay is not flooded.
      const mailResp = await ctx.request.get(`${MAILPIT_URL}/api/v1/messages`, {
        headers: { Accept: 'application/json' },
      });
      if (mailResp.ok()) {
        const body = await mailResp.json() as { messages: unknown[]; total?: number };
        const count = body.total ?? body.messages?.length ?? 0;
        expect(
          count,
          `N1: Mailpit received ${count} emails; expected ≤ ${MAX_EMAILS_DELIVERED} ` +
          '(email amplification must be bounded by rate-limit)',
        ).toBeLessThanOrEqual(MAX_EMAILS_DELIVERED);
      } else {
        console.warn('[N1] Mailpit not reachable — email count check skipped');
      }
    },
  );

  // N2: Wrong-password throttle.
  test.fixme(
    'N2 — rapid wrong-password attempts return 429 before the burst limit (brute-force throttle)',
    async ({ page, baseURL }) => {
      // TODO(MEDIUM-B): configure Kratos
      // password-method rate-limiting or Caddy rate_limit on the submit path.
      //
      // Implementation sketch:
      //   1. Initiate a login flow (GET /self-service/login/browser).
      //   2. Submit WRONG_PASSWORD_BURST + 2 wrong passwords via POST to
      //      flow.ui.action with method: 'password'.
      //   3. Assert a 429 is received at or before WRONG_PASSWORD_BURST + 1.
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
          headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
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
