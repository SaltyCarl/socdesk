import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

// Standalone from vite.config.ts on purpose: the verdict library is pure logic
// (no React, no DOM, no CSS), so tests run in a plain Node environment with none
// of the app's plugins. Keeps the doctrine layer honest about being a portable,
// side-effect-free module.
//
// The verdict/doctrine/map/client tests + the card-model baseline tests now live
// beside the shared source they cover (../shared), so both trees are scanned.
export default defineConfig({
  // No @vitejs/plugin-react here (see above), so esbuild's own JSX transform
  // handles the .tsx test files that render a shared/analyzer-ui component
  // (e.g. PartialDecodeNotice) via react-dom/server. Without this, esbuild's
  // default classic-runtime transform emits bare `React.createElement(...)`
  // calls with no React import in scope — pin the automatic runtime instead.
  esbuild: {
    jsx: 'automatic',
  },
  resolve: {
    // Mirrors vite.config.ts's alias (not imported wholesale — see above)
    // so web/src tests can import shared modules the same way app code does,
    // e.g. `@socdesk/shared/indicators`.
    alias: {
      '@socdesk/shared': fileURLToPath(new URL('../shared', import.meta.url)),
    },
    // A shared/ module that USES (not merely imports) a react hook — e.g.
    // useInlineEnrich — needs this: shared/ has no node_modules on its own
    // walk-up, so vite-node's SSR resolution of the bare 'react' specifier
    // from a file that far outside web/ mis-resolves without a pinned dedupe
    // target. Mirrors vite.config.ts's dedupe for the same reason.
    dedupe: ['react', 'react-dom'],
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx', '../shared/**/*.test.ts', '../shared/**/*.test.tsx', '../lib/**/*.test.mjs'],
  },
})
