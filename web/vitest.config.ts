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
  resolve: {
    // Mirrors vite.config.ts's alias (not imported wholesale — see above)
    // so web/src tests can import shared modules the same way app code does,
    // e.g. `@socdesk/shared/indicators`.
    alias: {
      '@socdesk/shared': fileURLToPath(new URL('../shared', import.meta.url)),
    },
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', '../shared/**/*.test.ts', '../lib/**/*.test.mjs'],
  },
})
