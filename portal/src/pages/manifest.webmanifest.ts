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
      icons: [
        { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
        { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
      ],
    }),
    { headers: { 'Content-Type': 'application/manifest+json' } },
  );
