// Dev-only stand-in for the script Kratos serves with a webauthn node, so `?dev-state=` pages can be walked after a
// ClientRouter swap with a script that loads like the real one. Answers 404 outside `astro dev`.

import type { APIRoute } from 'astro';

export const prerender = false;

const STUB = `
(function () {
  var mark = function (n) { document.documentElement.dataset.webauthnCalls = String((+document.documentElement.dataset.webauthnCalls || 0) + 1) + ':' + n; };
  window.oryWebAuthnRegistration = function () { mark('webauthn'); };
  window.oryPasskeySettingsRegistration = function () { mark('passkey'); };
})();
`;

export const GET: APIRoute = () =>
  import.meta.env.DEV
    ? new Response(STUB, { headers: { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store' } })
    : new Response('Not found', { status: 404 });
