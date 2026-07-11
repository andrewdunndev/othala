import { defineConfig } from 'astro/config';

// othala.dunn.dev — public documentation site.
//
// Static SSG, modelled on reference.dunn.dev. Unlike the reference
// site (which aliases `@dunn.dev/reference` back to its own repo root
// to dog-food the package), othala is an ordinary CONSUMER of the
// estate design system: the tokens + chrome arrive via the published
// `@dunn.dev/reference` npm package (see site/.npmrc for the registry,
// and src/styles/global.css for the imports). This is the same wiring
// the othala portal already uses.
export default defineConfig({
  site: 'https://othala.dunn.dev',
  output: 'static',
  trailingSlash: 'always',
  build: { format: 'directory' },
});
