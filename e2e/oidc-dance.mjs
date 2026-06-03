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
// __SUBJECT__ / __KEEP_SECRET__ are sed-substituted by smoke.sh before piping.
// Output: single line `OK claims={...}` on success, or `DENIED-at-...` / `EXC`.

import { OAuth2Api, Configuration } from '@ory/client-fetch';
import { CookieJar } from 'tough-cookie';
import makeFetchCookie from 'fetch-cookie';
import { decodeJwt } from 'jose';

const HP = 'http://hydra:4444';
const HA = 'http://hydra:4445';
// APP is the othala public SSR port. When running inside the othala container
// this is localhost:8080; when running from the playwright container (which
// has the npm deps) this must be the service name: othala:8080.
// smoke.sh run_dance now execs into the playwright container after npm ci.
const APP = process.env.OTHALA_URL ?? 'http://othala:8080';
const CLIENT = 'keep';
const REDIRECT = 'https://keep.dunn.dev/identity/connect/oidc-signin';
const SUBJECT = '__SUBJECT__';
const SECRET = '__KEEP_SECRET__';

// Cookie jar — RFC-compliant, handles Domain/Path/Secure/SameSite attributes.
// tough-cookie rejects 'secure' cookies on http:// by default; the e2e is HTTP
// only, so we use a relaxed options object.
const jar = new CookieJar(undefined, { rejectPublicSuffixes: false, looseMode: true });
// fetch-cookie wraps globalThis.fetch (Node 18+) with automatic jar management.
// Hydra sets CSRF cookies on the OAuth2 flow that must survive the login/consent
// redirect chain; tough-cookie handles the persistence the old manual accumulator did.
const fetchWithCookies = makeFetchCookie(fetch, jar);

// Hydra admin API client for the login accept call.
const hydraAdmin = new OAuth2Api(new Configuration({ basePath: HA }));

// Rewrite Hydra's external-facing redirect_to URLs (which embed the configured
// issuer host, e.g. auth.othala.test) to the internal hydra:4444 endpoint so we
// can follow them from inside the compose net without DNS for auth.othala.test.
// Hydra's redirect_to URLs carry the external issuer host (auth.othala.test).
// Rewrite to internal addresses. Ordering matters: app-challenge paths (/oauth2/login,
// /oauth2/consent) must be matched BEFORE the generic /oauth2 prefix or they'd be
// routed to hydra:4444 instead of the app.
const toInternal = (u) => {
  try {
    const x = new URL(u);
    // Challenge handlers are served by the app, not Hydra.
    if (x.pathname.startsWith('/oauth2/login') || x.pathname.startsWith('/oauth2/consent') || x.pathname.startsWith('/oauth2/logout')) {
      return APP + x.pathname + x.search;
    }
    // Remaining /oauth2/* and /.well-known/* are Hydra's public surface.
    if (x.pathname.startsWith('/oauth2') || x.pathname.startsWith('/.well-known')) {
      return HP + x.pathname + x.search;
    }
    // Fallback: rewrite to hydra for any unrecognised hydra-issued URL.
    return HP + x.pathname + x.search;
  } catch {
    return u;
  }
};

const loc = (r) => r.headers.get('location');

(async () => {
  try {
    // ── Step 1: authorization request → redirect with login_challenge ─────────
    const authUrl =
      HP + '/oauth2/auth?client_id=' + CLIENT +
      '&response_type=code' +
      '&scope=' + encodeURIComponent('openid email groups') +
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
    let r3 = await fetchWithCookies(toInternal(redirectTo), { redirect: 'manual' });
    const l3 = loc(r3);
    const consentChallenge = l3 ? new URL(l3, HP).searchParams.get('consent_challenge') : null;
    if (!consentChallenge) {
      console.log('STEP3 no consent_challenge status=' + r3.status + ' loc=' + l3);
      return;
    }

    // ── Step 4: drive the APP consent handler (re-gates + composes claims) ────
    // The URL is the app's /oauth2/consent handler, routed via APP (othala:8080).
    const consentHandlerUrl = APP + '/oauth2/consent?consent_challenge=' + consentChallenge;
    let r4 = await fetchWithCookies(consentHandlerUrl, { redirect: 'manual' });
    const l4 = loc(r4);
    if (!l4) {
      console.log('STEP4 consent no location status=' + r4.status + ' body=' + (await r4.text()).slice(0, 200));
      return;
    }
    const u4 = new URL(l4, APP);
    if (u4.searchParams.get('error')) {
      console.log('DENIED-at-consent error=' + u4.searchParams.get('error') + ' desc=' + u4.searchParams.get('error_description'));
      return;
    }

    // ── Step 5: follow consent verifier → Hydra issues the auth code ──────────
    let r5 = await fetchWithCookies(toInternal(l4), { redirect: 'manual' });
    const l5 = loc(r5);
    if (!l5) {
      console.log('STEP5 no location status=' + r5.status + ' body=' + (await r5.text()).slice(0, 200));
      return;
    }
    const u5 = new URL(l5, APP);
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

    const keepRoles = claims?.resource_access?.keep?.roles;
    console.log('OK claims=' + JSON.stringify({
      sub: claims.sub,
      email: claims.email,
      groups: claims.groups,
      keep_roles: keepRoles,
      introspect_active: intro.active,
    }));
  } catch (e) {
    console.log('EXC ' + e.message);
  }
})();
