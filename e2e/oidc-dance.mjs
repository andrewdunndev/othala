// e2e fixture: a browser-free OIDC authorization-code dance, run INSIDE othala's
// node (smoke.sh Section G pipes this through `docker compose exec -T othala node`).
//
// A real browser would: log in via the Kratos UI (minting a session cookie), then
// let Hydra drive login -> consent -> code -> token. We can't render a browser in
// compose, so we forge the LOGIN via the Hydra admin API (no cookie needed) and
// then drive the APP's consent handler directly — which is the security-critical
// half: it re-gates on the subject (state + access group) and composes the id_token
// claims. We then exchange the code and decode the id_token.
//
// This proves, end-to-end against live Kratos + Hydra:
//   - the converged challenge surface issues a real ID token (GAP-1),
//   - manifest-driven claims injection lands in that token (GAP-2 — the role claim
//     that the CU1 convergence silently dropped, restored + guarded),
//   - the access-gate denies inactive identities and missing-group members at the
//     consent re-gate (GAP-3).
//
// __SUBJECT__ / __KEEP_SECRET__ are sed-substituted by smoke.sh before piping.
// Output is a single line: `OK claims={...}` on success (with keep_roles), or
// `DENIED-at-{consent,code} ...` when the gate rejects, or `STEP#/EXC ...` on a
// harness/plumbing error.
const HP = 'http://hydra:4444', HA = 'http://hydra:4445', APP = 'http://localhost:8080';
const CLIENT = 'keep', REDIRECT = 'https://keep.dunn.dev/identity/connect/oidc-signin';
const SUBJECT = '__SUBJECT__', SECRET = '__KEEP_SECRET__';
// Cookie jar: Hydra sets CSRF cookies on the OAuth2 flow that must be carried
// across the login/consent redirect chain. node fetch has no jar, so accumulate
// Set-Cookie and replay it on every request.
const jar = {};
const stash = (r) => { const sc = r.headers.getSetCookie ? r.headers.getSetCookie() : []; for (const c of sc) { const kv = c.split(';')[0]; const i = kv.indexOf('='); if (i > 0) jar[kv.slice(0, i).trim()] = kv.slice(i + 1).trim(); } };
const nf = async (u, o = {}) => { const ck = Object.entries(jar).map(([k, v]) => k + '=' + v).join('; '); const r = await fetch(u, { ...o, redirect: 'manual', headers: { ...(o.headers || {}), ...(ck ? { Cookie: ck } : {}) } }); stash(r); return r; };
const loc = (r) => r.headers.get('location');
// Hydra builds redirect URLs from its issuer host (auth-lab.*), not the internal
// container name — rewrite to hydra:4444 so we can follow them inside the net.
const hy = (u) => { const x = new URL(u, HP); return HP + x.pathname + x.search; };
(async () => {
  try {
    // 1. authorization request -> redirect to the app login URL w/ login_challenge
    const au = HP + '/oauth2/auth?client_id=' + CLIENT + '&response_type=code&scope='
      + encodeURIComponent('openid email groups') + '&redirect_uri=' + encodeURIComponent(REDIRECT)
      + '&state=dancestate01&nonce=dancenonce01';
    let r = await nf(au);
    let l = loc(r);
    if (!l) { console.log('STEP1 no location status=' + r.status + ' body=' + (await r.text()).slice(0, 200)); return; }
    const lc = new URL(l, HP).searchParams.get('login_challenge');
    if (!lc) { console.log('STEP1 no login_challenge in ' + l); return; }

    // 2. forge login acceptance via the admin API (bypasses the cookie-bound login UI)
    let ra = await fetch(HA + '/admin/oauth2/auth/requests/login/accept?login_challenge=' + lc,
      { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ subject: SUBJECT, remember: false }) });
    let raj = await ra.json();
    if (!raj.redirect_to) { console.log('STEP2 no redirect_to status=' + ra.status + ' ' + JSON.stringify(raj)); return; }

    // 3. follow -> Hydra issues the consent_challenge (to the app consent URL)
    let r2 = await nf(hy(raj.redirect_to));
    let l2 = loc(r2);
    const cc = l2 ? new URL(l2, HP).searchParams.get('consent_challenge') : null;
    if (!cc) { console.log('STEP3 no consent_challenge status=' + r2.status + ' loc=' + l2); return; }

    // 4. drive the APP consent handler (re-gates on subject + composes claims)
    let r3 = await nf(APP + '/oauth2/consent?consent_challenge=' + cc);
    let l3 = loc(r3);
    if (!l3) { console.log('STEP4 consent no location status=' + r3.status + ' body=' + (await r3.text()).slice(0, 200)); return; }
    let u3 = new URL(l3, APP);
    if (u3.searchParams.get('error')) { console.log('DENIED-at-consent error=' + u3.searchParams.get('error') + ' desc=' + u3.searchParams.get('error_description')); return; }

    // 5. follow the consent verifier -> Hydra issues the auth code
    let r4 = await nf(hy(l3));
    let l4 = loc(r4);
    if (!l4) { console.log('STEP5 no location status=' + r4.status + ' body=' + (await r4.text()).slice(0, 200)); return; }
    let u4 = new URL(l4, APP);
    if (u4.searchParams.get('error')) { console.log('DENIED-at-code error=' + u4.searchParams.get('error') + ' desc=' + u4.searchParams.get('error_description')); return; }
    const code = u4.searchParams.get('code');
    if (!code) { console.log('STEP5 no code in ' + l4); return; }

    // 6. token exchange (client_secret_basic) -> decode the id_token
    const basic = Buffer.from(CLIENT + ':' + SECRET).toString('base64');
    let rt = await fetch(HP + '/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic ' + basic },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT }),
    });
    let tok = await rt.json();
    if (!tok.id_token) { console.log('STEP6 no id_token status=' + rt.status + ' ' + JSON.stringify(tok)); return; }
    const p = JSON.parse(Buffer.from(tok.id_token.split('.')[1], 'base64url').toString());
    console.log('OK claims=' + JSON.stringify({ sub: p.sub, email: p.email, groups: p.groups, keep_roles: p && p.resource_access && p.resource_access.keep && p.resource_access.keep.roles }));
  } catch (e) { console.log('EXC ' + e.message); }
})();
