import { defineConfig } from 'vitest/config'

// Standalone from vite.config.ts on purpose: the verdict library is pure logic
// (no React, no DOM, no CSS), so tests run in a plain Node environment with none
// of the app's plugins. Keeps the doctrine layer honest about being a portable,
// side-effect-free module.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
})
