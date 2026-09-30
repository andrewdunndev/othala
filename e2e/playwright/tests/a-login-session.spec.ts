// A — a JSON-API login yields an active Kratos session tied to the right identity (the login widget is bypassed).

import { test, expect } from '../fixtures';
import { loginViaJsonApi } from '../actions/login';
import { getSession } from '../actions/session';

test('A — member login establishes a real Kratos session', async ({
  ctx,
  baseURL,
  member,
}) => {
  const sessionCookie = await loginViaJsonApi(
    ctx,
    { identifier: member.email, password: member.password },
    baseURL,
  );
  console.log('[A] session cookie set:', sessionCookie !== '(no session cookie found)');

  const whoami = await getSession(ctx, baseURL);

  expect(whoami).not.toBeNull();
  expect(whoami!.active).toBe(true);
  expect(whoami!.identity?.traits?.email).toBe(member.email);
});
