// The PWA manifest, named for the deployment.

import type { APIRoute } from 'astro';
import { instanceName } from '../lib/config';

export const prerender = false;

export const GET: APIRoute = () =>
  new Response(
    JSON.stringify({
      name: instanceName,
      short_name: instanceName,
      description: 'Single sign-on portal.',
      start_url: '/',
      display: 'standalone',
      theme_color: '#4a6741',
      background_color: '#ffffff',
      icons: [],
    }),
    { headers: { 'Content-Type': 'application/manifest+json' } },
  );
