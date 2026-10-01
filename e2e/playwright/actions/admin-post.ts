/**
 * admin-post.ts — post an admin action the page does not offer.
 *
 * The person page withholds actions the server would refuse, so a test of the server guard takes a CSRF token from the
 * form of a person for whom the action IS offered (tokens bind to the admin and the action, not the target) and posts
 * it at the target by hand.
 */

import type { APIResponse, BrowserContext, Page } from '@playwright/test';

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
