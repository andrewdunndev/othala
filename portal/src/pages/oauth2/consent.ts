// Public OAuth2 consent challenge provider.
//
// GET  /oauth2/consent?consent_challenge=...
//   Called by Hydra when it redirects the browser to the consent provider.
//   For skip_consent:true clients (the first-party default),
//   handleConsent auto-accepts (skip path). For clients with
//   skip_consent:false, handleConsent 302-bounces to /auth/consent to
//   render the grant screen.
//
// POST /oauth2/consent
//   Called by the <form> in /auth/consent.astro when the user clicks Allow or
//   Deny. Validates CSRF + subject-match, then accepts or rejects the challenge.

import type { APIRoute } from 'astro';
import { handleConsent, handleConsentPost } from '../../lib/oauth2-handlers';

export const prerender = false;

export const GET: APIRoute = ({ request }) => handleConsent(request);

export const POST: APIRoute = ({ request }) => handleConsentPost(request);
