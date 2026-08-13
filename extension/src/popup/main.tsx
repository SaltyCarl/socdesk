// popup/main.tsx — PHASE 1 PLACEHOLDER popup.
//
// This is NOT the real popup UX (that is Phase 2). Its only job is to prove the
// pipeline end-to-end: that a shared React card component from
// `@socdesk/shared/verdict-cards` compiles and mounts inside the extension's own
// Vite/React build, under MV3's default page CSP (script-src 'self'
// 'wasm-unsafe-eval'; no eval, no remote code). We render the AnalystVerdict
// register — the dense console card intended for the extension — fed a static
// STUBS fixture from the shared package.

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '../index.css'
import { initTheme } from '@socdesk/shared/lib/theme'
import { AnalystVerdict, STUBS } from '@socdesk/shared/verdict-cards'

// Resolve the theme before first paint to avoid a light/dark flash (the product
// default is dark; a stored preference or the OS setting wins).
initTheme()

const fixture = STUBS[0].data

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <div className="p-4">
      <p className="mb-3 font-mono text-micro tracking-label text-faint uppercase">
        Phase 1 pipeline check · shared card
      </p>
      <AnalystVerdict data={fixture} />
    </div>
  </StrictMode>,
)
