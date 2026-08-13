// popup/main.tsx — the toolbar popup entry.
//
// Mounts the React popup, which paste-or-context-menu classifies an indicator,
// calls the LIVE /api/enrich on the configured origin through the shared verdict
// client, and renders the shared AnalystVerdict card + copy-out actions.

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '../index.css'
import { initTheme } from '@socdesk/shared/lib/theme'
import { Popup } from './Popup'

// Resolve the theme before first paint to avoid a light/dark flash (the product
// default is dark; a stored preference or the OS setting wins).
initTheme()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Popup />
  </StrictMode>,
)
