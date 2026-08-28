import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

/**
 * A plain SPA served by whatever the customer already runs.
 *
 * Deliberately not a framework with a hosting vendor attached: a
 * cryptographic inventory tool is deployed inside a perimeter, often an
 * air-gapped one, and `vite build` produces static files that any web server
 * can serve. The API is reached at runtime, so the same bundle works against
 * localhost, a staging box, or an internal deployment without a rebuild.
 */
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    port: 3000,
    // Same-origin in development, so no CORS and no API URL baked into the bundle.
    proxy: {
      '/api': {
        target: process.env['ASSAY_API'] ?? 'http://localhost:3001',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ''),
      },
    },
  },
  build: { outDir: 'dist', sourcemap: true },
});
