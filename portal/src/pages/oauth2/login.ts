// Public OAuth2 login challenge provider: GET /oauth2/login?login_challenge=...
// (Hydra login provider role; distinct from the /auth/login human UI.)
import type { APIRoute } from 'astro';
import { handleLogin } from '../../lib/oauth2-handlers';

export const prerender = false;

export const GET: APIRoute = ({ request }) => handleLogin(request);
