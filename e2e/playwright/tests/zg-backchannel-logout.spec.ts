// ZG — Force re-login posts a back-channel logout token for the member's login session.

import { createServer } from 'node:http';
import { decodeJwt } from 'jose';
import { test, expect, adminAal2Context, GRAFANA_CLIENT_ID, GRAFANA_REDIRECT_URI, KRATOS_ADMIN_URL } from '../fixtures';
import { createIdentityWithPassword, TEST_PASSWORD } from '../actions/identity';
import { loginViaJsonApi } from '../actions/login';
import { walk } from '../actions/oidc';

test('ZG — force re-login delivers a logout token carrying the session sid', async ({ browser, baseURL, hydraPublicURL }) => {
  const secret = process.env.GRAFANA_CLIENT_SECRET;
  if (!secret) throw new Error('GRAFANA_CLIENT_SECRET not set — inject from compose environment');
  const suffix = Date.now();
  const admin = await createIdentityWithPassword({
    email: `zg.admin.${suffix}@othala.test`,
    username: `zg.admin.${suffix}`,
    displayName: 'ZG Admin',
    groups: [],
    isAdmin: true,
    kratosAdminURL: KRATOS_ADMIN_URL,
  });
  const member = await createIdentityWithPassword({
    email: `zg.member.${suffix}@othala.test`,
    username: `zg.member.${suffix}`,
    displayName: 'ZG Member',
    groups: ['grafana-access'],
    kratosAdminURL: KRATOS_ADMIN_URL,
  });

  const tokens: string[] = [];
  const sink = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const t = new URLSearchParams(body).get('logout_token');
      if (t) tokens.push(t);
      res.writeHead(200).end();
    });
  });
  await new Promise<void>((resolve) => sink.listen(4500, '0.0.0.0', resolve));

  const memberCtx = await browser.newContext();
  const adminCtx = await adminAal2Context({ browser, email: admin.email, password: TEST_PASSWORD, baseURL: baseURL! });
  try {
    await loginViaJsonApi(memberCtx, { identifier: member.email, password: TEST_PASSWORD }, baseURL!);
    const authorize =
      `${baseURL}/oauth2/auth?client_id=${GRAFANA_CLIENT_ID}&response_type=code` +
      `&scope=${encodeURIComponent('openid email groups')}&redirect_uri=${encodeURIComponent(GRAFANA_REDIRECT_URI)}` +
      `&state=zg-state&nonce=zg-nonce`;
    const chain = await walk(memberCtx, baseURL!, authorize, (loc) => loc.href.startsWith('https://grafana.othala.test'));
    const code = chain.at(-1)?.searchParams.get('code');
    expect(code, `authorize must end in a code; chain: ${chain.map(String).join(' -> ')}`).toBeTruthy();
    const basic = Buffer.from(`${GRAFANA_CLIENT_ID}:${secret}`).toString('base64');
    const exchange = await memberCtx.request.post(`${hydraPublicURL}/oauth2/token`, {
      headers: { Authorization: `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      form: { grant_type: 'authorization_code', code: code!, redirect_uri: GRAFANA_REDIRECT_URI },
    });
    expect(exchange.ok(), `code exchange failed: ${exchange.status()}`).toBe(true);
    const sid = decodeJwt((await exchange.json()).id_token as string).sid;
    expect(sid, 'id_token must carry sid').toBeTruthy();

    const page = await adminCtx.newPage();
    const targetUrl = `${baseURL}/admin/users/${member.id}`;
    await page.goto(targetUrl, { waitUntil: 'networkidle' });
    const [resp] = await Promise.all([
      page.waitForResponse((r) => r.url().startsWith(targetUrl) && r.request().method() === 'POST'),
      page.getByRole('button', { name: 'Force re-login' }).click(),
    ]);
    expect([200, 303], `force re-login status ${resp.status()}`).toContain(resp.status());

    await expect.poll(() => tokens.length, { timeout: 10_000 }).toBeGreaterThan(0);
    const logout = decodeJwt(tokens[0]);
    expect(logout.sid).toBe(sid);
    expect(logout.aud).toEqual([GRAFANA_CLIENT_ID]);
    expect(Object.keys(logout.events as object)).toContain('http://schemas.openid.net/event/backchannel-logout');
  } finally {
    await memberCtx.close();
    await adminCtx.close();
    await new Promise((resolve) => sink.close(resolve));
  }
});
