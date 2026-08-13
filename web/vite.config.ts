import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    // CSP posture (inviolate): never inline assets as base64 data: URIs into
    // the JS/CSS bundle. Everything ships as an external /assets/* file so
    // `default-src 'none'` + `script-src 'self'` + `style-src 'self'` hold.
    assetsInlineLimit: 0,
  },
})
