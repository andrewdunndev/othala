// e2e fixture: browser-free OIDC authorization-code dance — Section G of smoke.sh.
//
// Runs inside the `dance-runner` compose oneshot service (playwright image, profile
// oneshot) via `docker compose --profile oneshot run --rm --no-deps -T dance-runner`.
// smoke.sh's run_dance() helper subs __SUBJECT__ / __KEEP_SECRET__ with sed and
// pipes the result to the container's stdin. The dance-runner entrypoint runs
// `npm ci && node` — node reads this script from stdin. npm deps (@ory/client-fetch,
// tough-cookie, fetch-cookie, jose) are installed from e2e/package.json.
//
// Rewritten from the bespoke jar+fetch accumulator onto:
//   @ory/client-fetch  — OAuth2Api.acceptOAuth2LoginRequest (admin-forged login)
//   tough-cookie + fetch-cookie — proper RFC-compliant cookie jar (replaces the
//                                 manual Set-Cookie accumulator)
//   jose               — decodeJwt for id_token claims (replaces manual base64url)
//   introspectOAuth2Token assertion — confirms active=true + sub matches
//
// __SUBJECT__ / __GRAFANA_SECRET__ are sed-substituted by smoke.sh before piping.
// Output: single line `OK claims={...}` on success, or `DENIED-at-...` / `EXC`.

import { OAuth2Api, Configuration } from '@ory/client-fetch';
import { CookieJar } from 'tough-cookie';
import makeFetchCookie from 'fetch-cookie';
import { decodeJwt } from 'jose';

const HP = process.env.EDGE_URL ?? 'https://auth.othala.test';
const HA = 'http://hydra:4445';
// grafana is the role-mapping client; its registered redirect_uri must
// byte-match the grafana fixture's redirect_uris[0].
const CLIENT = 'grafana';
const REDIRECT = 'https://grafana.othala.test/login/generic_oauth';
const SUBJECT = '__SUBJECT__';
const SECRET = '__GRAFANA_SECRET__';
// Picture mode: a non-empty base64 PNG and the hash of the avatar stored on SUBJECT add the profile-scope checks.
const SCOPE = '__SCOPE__';
const PNG_B64 = '__PNG_B64__';
const PICTURE_SHA = '__PICTURE_SHA__';
// A skip_consent client is accepted only for the browser whose Kratos session is the subject, so a subject with
// credentials signs in at Kratos first; one without (inactive, no access) is denied before a session matters.
const EMAIL = '__EMAIL__';
const PASSWORD = '__PASSWORD__';
// Set, the script only trades this refresh token at the token endpoint and prints the status.
const REFRESH_TOKEN = '__REFRESH_TOKEN__';

// Hydra's CSRF cookies are Secure, so every hop goes through the https edge.
const jar = new CookieJar();
// fetch-cookie wraps globalThis.fetch (Node 18+) with automatic jar management.
// Hydra sets CSRF cookies on the OAuth2 flow that must survive the login/consent
// redirect chain; tough-cookie handles the persistence the old manual accumulator did.
const fetchWithCookies = makeFetchCookie(fetch, jar);

// Hydra admin API client for the login accept call.
const hydraAdmin = new OAuth2Api(new Configuration({ basePath: HA }));

const loc = (r) => r.headers.get('location');

async function pictureChecks(claims, accessToken) {
  const url = HP + '/avatar/' + SUBJECT + '/' + PICTURE_SHA.slice(0, 16);
  const want = Buffer.from(PNG_B64, 'base64');
  const ok = await fetch(url);
  const body = Buffer.from(await ok.arrayBuffer());
  const bad = await fetch(HP + '/avatar/' + SUBJECT + '/' + '0'.repeat(16));
  const info = await fetch(HP + '/userinfo', { headers: { Authorization: 'Bearer ' + accessToken } });
  const infoClaims = await info.json().catch(() => ({}));
  return {
    claim_ok: claims.picture === url,
    claim: claims.picture,
    get_status: ok.status,
    get_type: ok.headers.get('content-type'),
    get_nosniff: ok.headers.get('x-content-type-options'),
    get_bytes_equal: body.equals(want),
    wrong_hash_status: bad.status,
    userinfo_status: info.status,
    userinfo_picture: infoClaims.picture,
  };
}

async function kratosLogin() {
  const flow = await (await fetchWithCookies(HP + '/self-service/login/browser', { headers: { Accept: 'application/json' } })).json();
  const csrf = (flow.ui?.nodes ?? []).find((n) => n.attributes?.name === 'csrf_token')?.attributes?.value ?? '';
  const res = await fetchWithCookies(flow.ui.action, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ method: 'password', identifier: EMAIL, password: PASSWORD, csrf_token: csrf }),
  });
  return res.ok;
}

async function refreshOnly() {
  const basic = Buffer.from(CLIENT + ':' + SECRET).toString('base64');
  const res = await fetch(HP + '/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: 'Basic ' + basic },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: REFRESH_TOKEN }),
  });
  console.log('REFRESH status=' + res.status);
}

(async () => {
  try {
    if (REFRESH_TOKEN) {
      await refreshOnly();
      return;
    }
    if (EMAIL) await kratosLogin();

    // ── Step 1: authorization request → redirect with login_challenge ─────────
    const authUrl =
      HP + '/oauth2/auth?client_id=' + CLIENT +
      '&response_type=code' +
      '&scope=' + encodeURIComponent(SCOPE) +
      '&redirect_uri=' + encodeURIComponent(REDIRECT) +
      '&state=dancestate01&nonce=dancenonce01';

    let r1 = await fetchWithCookies(authUrl, { redirect: 'manual' });
    const l1 = loc(r1);
    if (!l1) {
      console.log('STEP1 no location status=' + r1.status + ' body=' + (await r1.text()).slice(0, 200));
      return;
    }
    const loginChallenge = new URL(l1, HP).searchParams.get('login_challenge');
    if (!loginChallenge) {
      console.log('STEP1 no login_challenge in ' + l1);
      return;
    }

    // ── Step 2: forge login acceptance via the Hydra admin API ────────────────
    // OAuth2Api.acceptOAuth2LoginRequest wraps the PUT /admin/oauth2/auth/requests/login/accept
    // call, returning the redirect_to URL.
    const acceptResp = await hydraAdmin.acceptOAuth2LoginRequest({
      loginChallenge,
      acceptOAuth2LoginRequest: { subject: SUBJECT, remember: false },
    });
    const redirectTo = acceptResp.redirect_to;
    if (!redirectTo) {
      console.log('STEP2 no redirect_to in acceptOAuth2LoginRequest response');
      return;
    }

    // ── Step 3: follow redirect_to → Hydra issues consent_challenge ───────────
    let r3 = await fetchWithCookies(redirectTo, { redirect: 'manual' });
    const l3 = loc(r3);
    const consentChallenge = l3 ? new URL(l3, HP).searchParams.get('consent_challenge') : null;
    if (!consentChallenge) {
      console.log('STEP3 no consent_challenge status=' + r3.status + ' loc=' + l3);
      return;
    }

    // ── Step 4: drive the APP consent handler (re-gates + composes claims) ────
    const consentHandlerUrl = HP + '/oauth2/consent?consent_challenge=' + consentChallenge;
    let r4 = await fetchWithCookies(consentHandlerUrl, { redirect: 'manual' });
    const l4 = loc(r4);
    if (!l4) {
      console.log('STEP4 consent no location status=' + r4.status + ' body=' + (await r4.text()).slice(0, 200));
      return;
    }
    const u4 = new URL(l4, HP);
    if (u4.searchParams.get('error')) {
      console.log('DENIED-at-consent error=' + u4.searchParams.get('error') + ' desc=' + u4.searchParams.get('error_description'));
      return;
    }

    // ── Step 5: follow consent verifier → Hydra issues the auth code ──────────
    let r5 = await fetchWithCookies(l4, { redirect: 'manual' });
    const l5 = loc(r5);
    if (!l5) {
      console.log('STEP5 no location status=' + r5.status + ' body=' + (await r5.text()).slice(0, 200));
      return;
    }
    const u5 = new URL(l5, HP);
    if (u5.searchParams.get('error')) {
      console.log('DENIED-at-code error=' + u5.searchParams.get('error') + ' desc=' + u5.searchParams.get('error_description'));
      return;
    }
    const code = u5.searchParams.get('code');
    if (!code) {
      console.log('STEP5 no code in ' + l5);
      return;
    }

    // ── Step 6: token exchange (client_secret_basic) ──────────────────────────
    const basic = Buffer.from(CLIENT + ':' + SECRET).toString('base64');
    const tokenResp = await fetch(HP + '/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: 'Basic ' + basic,
      },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT }),
    });
    const tok = await tokenResp.json();
    if (!tok.id_token) {
      console.log('STEP6 no id_token status=' + tokenResp.status + ' ' + JSON.stringify(tok));
      return;
    }

    // ── Step 7: decode id_token with jose ─────────────────────────────────────
    const claims = decodeJwt(tok.id_token);

    // ── Step 8: introspect access_token (active=true + sub match) ─────────────
    const introspectResp = await fetch(HA + '/admin/oauth2/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: tok.access_token }),
    });
    const intro = await introspectResp.json();
    if (!intro.active || intro.sub !== SUBJECT) {
      console.log('STEP8 introspect failed active=' + intro.active + ' sub=' + intro.sub + ' want=' + SUBJECT);
      return;
    }

    // grafana's consent block emits a `grafana_role` JMESPath array claim
    // per identity group (family -> Viewer). The smoke asserts on it.
    const picture = PNG_B64 ? await pictureChecks(claims, tok.access_token) : undefined;
    const grafanaRole = claims?.grafana_role;
    console.log('OK claims=' + JSON.stringify({
      sub: claims.sub,
      email: claims.email,
      groups: claims.groups,
      grafana_role: grafanaRole,
      introspect_active: intro.active,
      refresh_token: tok.refresh_token,
      picture,
    }));
  } catch (e) {
    console.log('EXC ' + e.message);
  }
})();
