/**
 * Mailpit helpers. Mailpit accumulates mail across runs in one lab session, so
 * every predicate must bound on `created` (forRecipient does, with 5s of skew).
 */

export const MAILPIT_API = process.env.MAILPIT_API ?? 'http://mailpit:8025';

export interface MailSummary {
  id: string;
  subject: string;
  to: string[];
  created: number;
}

export async function listMail(): Promise<MailSummary[]> {
  const resp = await fetch(`${MAILPIT_API}/api/v1/messages`);
  if (!resp.ok) throw new Error(`mailpit /api/v1/messages returned ${resp.status}`);
  const data = (await resp.json()) as {
    messages?: Array<{ ID: string; Subject: string; To: Array<{ Address: string }>; Created: string }>;
  };
  return (data.messages ?? [])
    .map((m) => ({
      id: m.ID,
      subject: m.Subject,
      to: m.To.map((t) => t.Address.toLowerCase()),
      created: Date.parse(m.Created),
    }))
    .sort((a, b) => b.created - a.created);
}

export async function mailBody(id: string): Promise<string> {
  const resp = await fetch(`${MAILPIT_API}/api/v1/message/${id}`);
  if (!resp.ok) throw new Error(`mailpit message fetch returned ${resp.status}`);
  const msg = (await resp.json()) as { Text?: string; HTML?: string };
  return msg.Text ?? msg.HTML ?? '';
}

export function forRecipient(to: string, since: number, subject?: RegExp) {
  return (m: MailSummary) =>
    m.to.includes(to.toLowerCase()) && m.created >= since - 5_000 && (!subject || subject.test(m.subject));
}

/** Newest message matching `match`; polls until `timeoutMs`, throws on timeout. */
export async function waitForMessage(
  match: (m: MailSummary) => boolean,
  timeoutMs = 15_000,
): Promise<MailSummary & { body: string; code: string }> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const hit = (await listMail()).find(match);
    if (hit) {
      const body = await mailBody(hit.id);
      return { ...hit, body, code: body.match(/\b(\d{6})\b/)?.[1] ?? '' };
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`Timed out waiting for mail after ${timeoutMs}ms`);
}

/** Text bodies of every message mailpit's search finds for `query`. */
export async function searchMailBodies(query: string): Promise<string[]> {
  const list = await fetch(`${MAILPIT_API}/api/v1/search?query=${encodeURIComponent(query)}`);
  if (!list.ok) throw new Error(`mailpit search returned ${list.status}`);
  const { messages = [] } = (await list.json()) as { messages?: Array<{ ID: string }> };
  const out: string[] = [];
  for (const m of messages) out.push(await mailBody(m.ID));
  return out;
}
