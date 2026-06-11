// POST /api/request — the dashboard contact/request form backend.
//
// Flow:
//   1. Parse the submission (urlencoded form OR JSON; name, type, message).
//   2. Rate-limit by client (in-process sliding window, lib/contact.ts).
//   3. Validate + normalize (lib/contact.ts) — fail-closed on anything bad.
//   4. Send to the operator via the SHARED courier SMTP (lib/mailer.ts, which
//      reads OTHALA_SMTP_CONNECTION_URI — the same URI kratos.yml's courier
//      uses). Recipient = config.contactRecipient (OTHALA_CONTACT_RECIPIENT,
//      required in production — set explicitly).
//
// Responses:
//   200 { ok: true }                          — accepted + sent
//   400 { ok: false, error }                  — validation failure (safe reason)
//   429 { ok: false, error } + Retry-After    — rate limited
//   415 { ok: false, error }                  — unsupported content type
//   500 { ok: false, error: 'send failed' }   — transport failure (NO internals)
//
// SMTP internals are never leaked: a MailerError is logged server-side and the
// client gets a generic 500. This mirrors the admin endpoints' error discipline.

import type { APIContext, APIRoute } from 'astro';
import { validateContact, rateLimit } from '../../lib/contact';
import { sendContactRequest, MailerError } from '../../lib/mailer';
import { contactRecipient } from '../../lib/config';

export const prerender = false;

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

/** Best-effort client key for the rate limiter.
 *
 * With `trustProxy: true` in the node adapter, @astrojs/node resolves
 * ctx.clientAddress from the X-Forwarded-For header that Caddy sets, so this
 * is the actual client IP — not the Caddy container IP shared by all requests.
 *
 * The XFF-header fallback has been removed: the leftmost XFF entry is
 * attacker-injectable and would let a caller bypass the rate limit by spoofing
 * a fresh IP on every request. With trustProxy configured, ctx.clientAddress
 * is authoritative; when it is unexpectedly absent we fail closed to 'unknown'
 * (a single shared bucket) rather than trusting attacker-controlled input. */
function clientKey(ctx: APIContext): string {
  try {
    if (ctx.clientAddress) return ctx.clientAddress;
  } catch {
    // @astrojs/node only exposes clientAddress for on-demand routes; guard anyway.
  }
  return 'unknown';
}

async function parseForm(
  request: Request,
): Promise<{ name?: unknown; type?: unknown; message?: unknown } | null> {
  const ct = (request.headers.get('content-type') ?? '').toLowerCase();
  if (ct.includes('application/json')) {
    try {
      const body = await request.json();
      return typeof body === 'object' && body !== null ? body : {};
    } catch {
      return null;
    }
  }
  if (
    ct.includes('application/x-www-form-urlencoded') ||
    ct.includes('multipart/form-data')
  ) {
    const fd = await request.formData();
    return {
      name: fd.get('name') ?? undefined,
      type: fd.get('type') ?? undefined,
      message: fd.get('message') ?? undefined,
    };
  }
  return null;
}

export const POST: APIRoute = async (ctx) => {
  // 1. Rate limit first — a flood shouldn't reach validation/SMTP.
  const rl = rateLimit(clientKey(ctx));
  if (!rl.allowed) {
    return json(429, { ok: false, error: 'Too many requests. Please try again later.' }, {
      'Retry-After': String(rl.retryAfterSec),
    });
  }

  // 2. Parse.
  const raw = await parseForm(ctx.request);
  if (raw === null) {
    return json(415, { ok: false, error: 'Unsupported content type.' });
  }

  // 3. Validate.
  const result = validateContact(raw);
  if (!result.ok) {
    return json(400, { ok: false, error: result.reason });
  }

  // 4. Send via the shared courier SMTP.
  try {
    await sendContactRequest({
      to: contactRecipient,
      fromName: result.value.name,
      requestType: result.value.type,
      message: result.value.message,
    });
  } catch (err) {
    // Log the real reason server-side; never echo SMTP internals to the client.
    if (err instanceof MailerError) {
      console.error(`[othala/api/request] ${err.message}`);
    } else {
      console.error('[othala/api/request] unexpected send error', err);
    }
    return json(500, { ok: false, error: 'Could not send your request right now. Please try again later.' });
  }

  return json(200, { ok: true });
};

// A bare GET is not an error worth a stack trace — return 405 with Allow.
export const GET: APIRoute = () =>
  json(405, { ok: false, error: 'Method not allowed.' }, { Allow: 'POST' });
