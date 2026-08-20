// panel/main.tsx — the side-panel entry (mirrors popup/main.tsx).
//
// Mounts the React panel, which reads the right-click handoff stashed by the
// background service worker and renders the local analyzer for a command or
// the shared escalation card for an indicator.

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '../index.css'
import { initTheme } from '@socdesk/shared/lib/theme'
import { Panel } from './Panel'

// Resolve the theme before first paint to avoid a light/dark flash (the product
// default is dark; a stored preference or the OS setting wins).
initTheme()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Panel />
  </StrictMode>,
)
