// Public OAuth2 consent provider. GET (Hydra's redirect): auto-accepts
// skip_consent clients via handleConsent, else bounces to /auth/consent.
// POST (the form there): validates CSRF + subject match, then accepts or
// rejects the challenge.

import type { APIRoute } from 'astro';
import { handleConsent, handleConsentPost } from '../../lib/oauth2-handlers';

export const prerender = false;

export const GET: APIRoute = ({ request }) => handleConsent(request);

export const POST: APIRoute = ({ request }) => handleConsentPost(request);
