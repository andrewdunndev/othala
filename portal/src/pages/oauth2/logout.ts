// Public OAuth2 logout challenge provider: GET /oauth2/logout?logout_challenge=...
import type { APIRoute } from 'astro';
import { handleLogout } from '../../lib/oauth2-handlers';

export const prerender = false;

export const GET: APIRoute = ({ request }) => handleLogout(request);
