/**
 * admin-post.ts — post an admin action the page does not offer.
 *
 * The person page withholds actions the server would refuse, so a test of the server guard takes a CSRF token from the
 * form of a person for whom the action IS offered (tokens bind to the admin and the action, not the target) and posts
 * it at the target by hand.
 */

import { expect, type APIResponse, type BrowserContext, type Page } from '@playwright/test';

/** The CSRF token inside the form that posts `action`, read from a person page where that action is offered. */
export async function csrfTokenFor(page: Page, action: string): Promise<string> {
  return page.locator(`form:has(input[name="action"][value="${action}"]) input[name="csrf_token"]`).first().inputValue();
}

/** POST an admin action at a person page the way the browser form would (urlencoded, same origin). */
export async function postAdminAction(
  ctx: BrowserContext,
  baseURL: string,
  personId: string,
  fields: Record<string, string>,
): Promise<APIResponse> {
  return ctx.request.post(`${baseURL}/admin/users/${personId}`, {
    form: fields,
    headers: { Origin: new URL(baseURL).origin },
  });
}

/**
 * The danger notice an admin page answers with, or undefined. The page answers 200 whether it accepted an action or
 * refused it, so a refused save is a notice carrying its reason, never a status.
 */
export function refusalOf(html: string): string | undefined {
  const text = html.match(/class="notice notice-danger[^"]*"[^>]*>([\s\S]*?)<\/div>/)?.[1]?.replace(/<[^>]*>/g, '').trim();
  return text || undefined;
}

/**
 * An admin action poster for one test. Each call says whether it expects a refusal, so a refused action cannot pass
 * unnoticed: an unexpected refusal fails with its text, and an expected one fails if the page accepted instead.
 * `tokenFrom` is a person for whom the action is offered; the token binds to the admin and the action, not the target.
 */
export function adminPoster(ctx: BrowserContext, page: Page, baseURL: string, label: string) {
  return async (
    target: string,
    tokenFrom: string,
    action: string,
    fields: Record<string, string> = {},
    expectRefusal = false,
  ): Promise<string> => {
    await page.goto(`${baseURL}/admin/users/${tokenFrom}`, { waitUntil: 'networkidle' });
    const token = await csrfTokenFor(page, action);
    expect(token, `${label}: ${action} is offered on the token page`).not.toBe('');
    const resp = await postAdminAction(ctx, baseURL, target, { csrf_token: token, action, ...fields });
    expect(resp.status(), `${label}: ${action} answers with the page`).toBe(200);
    const html = await resp.text();
    const refusal = refusalOf(html);
    if (expectRefusal) expect(refusal, `${label}: ${action} is refused`).toBeTruthy();
    else expect(refusal, `${label}: ${action} was refused: ${refusal}`).toBeUndefined();
    return html;
  };
}
