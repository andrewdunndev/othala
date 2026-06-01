// Public OAuth2 consent challenge provider: GET /oauth2/consent?consent_challenge=...
import type { APIRoute } from 'astro';
import { handleConsent } from '../../lib/oauth2-handlers';

export const prerender = false;

export const GET: APIRoute = ({ request }) => handleConsent(request);
