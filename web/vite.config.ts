import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      // Framework-agnostic + shared React source consumed as TS/TSX (no
      // separate build), shared with the browser extension in a later phase.
      '@socdesk/shared': fileURLToPath(new URL('../shared', import.meta.url)),
    },
    // The shared/ source lives outside web/ and has no node_modules on its own
    // walk-up; force these bare deps to resolve from web's copy so a single
    // React instance is used across the app + shared modules.
    dedupe: ['react', 'react-dom', 'motion'],
  },
  build: {
    // CSP posture (inviolate): never inline assets as base64 data: URIs into
    // the JS/CSS bundle. Everything ships as an external /assets/* file so
    // `default-src 'none'` + `script-src 'self'` + `style-src 'self'` hold.
    assetsInlineLimit: 0,
  },
})
