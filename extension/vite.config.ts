import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { cpSync } from 'node:fs'
import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

const here = dirname(fileURLToPath(import.meta.url))

/**
 * copy-mv3-assets — copy the files that live OUTSIDE the bundler graph into
 * dist/ so it is a complete, loadable unpacked MV3 extension:
 *   • manifest.json — authored by hand, never imported.
 *   • icons/        — referenced only by manifest.json, which Vite never parses.
 * Fonts are NOT copied here: the shared tokens.css references them via
 * root-absolute url('/fonts/*.woff2'), which Vite resolves against extension/
 * and emits (hashed) into dist/assets/, rewriting the @font-face src for us.
 */
function copyMv3Assets(): Plugin {
  return {
    name: 'copy-mv3-assets',
    apply: 'build',
    closeBundle() {
      const out = join(here, 'dist')
      cpSync(join(here, 'manifest.json'), join(out, 'manifest.json'))
      cpSync(join(here, 'icons'), join(out, 'icons'), { recursive: true })
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss(), copyMv3Assets()],
  resolve: {
    alias: {
      // Framework-agnostic + shared React source consumed as TS/TSX (no separate
      // build), shared with the web app. Same alias the web build uses.
      '@socdesk/shared': fileURLToPath(new URL('../shared', import.meta.url)),
    },
    // The shared/ source lives outside extension/ and has no node_modules on its
    // own walk-up; force these bare deps to resolve from the extension's copy so
    // a single React instance is used across the popup + shared modules.
    dedupe: ['react', 'react-dom', 'motion'],
  },
  build: {
    // CSP posture: never inline assets as base64 data: URIs. Everything ships as
    // an external file so the default MV3 page policy holds cleanly.
    assetsInlineLimit: 0,
    rollupOptions: {
      // MULTI-ENTRY: the extension pages (loaded as HTML) + the background
      // service worker (a bare JS entry, referenced by manifest.json).
      input: {
        popup: join(here, 'popup.html'),
        options: join(here, 'options.html'),
        panel: join(here, 'panel.html'),
        background: join(here, 'src', 'background.ts'),
      },
      output: {
        // SHARP EDGE: manifest.json names the service worker as a LITERAL string
        // ("background.js"), so its output path must be STABLE and unhashed. Pin
        // just the background entry to a fixed name; the popup/options entries
        // and any shared chunks may be hashed because they load via the emitted
        // HTML (which the bundler rewrites every build) — and background.js's own
        // internal imports are rewritten to match within each build, so the
        // manifest reference never breaks.
        entryFileNames: (chunk) =>
          chunk.name === 'background' ? 'background.js' : 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
})
