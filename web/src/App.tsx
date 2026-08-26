import { useEffect, useState, type ReactNode } from 'react'
import { Shell, type ContainerSize } from './components/shell'
import { Overview } from './routes/Overview'
import { LookupRedirect } from './routes/LookupRedirect'
import { PowerShellAnalyzer } from './routes/PowerShellAnalyzer'
import { DataDeskRoute } from './routes/DataDeskRoute'
import { ActorProfileRoute } from './routes/ActorProfileRoute'
import { Gallery } from './routes/Gallery'
import { MyReports } from './routes/MyReports'
import { Admin } from './routes/Admin'
import { Privacy } from './routes/Privacy'
import { About } from './routes/About'

/**
 * App router — a tiny pathname read (no router dependency) drives a small
 * suffix→component table. Vite preview / Cloudflare Pages both fall back to
 * index.html, so client routing resolves from any deep link.
 *
 *   /         → home (globe hero + omnibar + start-of-shift board). nav:false —
 *               reached by the wordmark and the ⌘K palette, not a tab: the nav
 *               carries destinations only, the landing is where you already are.
 *   /lookup   → redirect stub → /#q=<same hash> (the omnibar is the lookup surface)
 *   /analyzer → the PowerShell analyzer (nav:false — the omnibar's command path;
 *               deep-linkable full-width surface for a heavy paste)
 *   /desk     → the data desk (feed / vulns / health / sources / ISP abuse)
 *   /actor    → Adversaries (the threat-actor / ransomware / malware directory)
 *   /gallery  → the design-system gallery (craft-review surface)
 *
 * In-app navigation (topbar links, command palette) goes through pushState +
 * a synthetic popstate (see palette/commands.ts::navigate), which `useRoute`
 * listens for.
 */

interface Route {
  path: string
  label: string
  size: ContainerSize
  el: ReactNode
  /** Show as a primary top-nav tab. Routable-but-hidden pages (e.g. the
   *  disclosure page, reached from the footer + palette) set this false. */
  nav?: boolean
}

const ROUTES: Route[] = [
  {
    path: '/',
    label: 'Home',
    // The root is reached by the wordmark (Topbar → href="/") and the ⌘K
    // palette, not a tab — nav carries destinations only, the landing is where
    // you already are. Analyzer/Lookup already fold into the same omni-input.
    nav: false,
    size: 'wide',
    el: (
      <Overview
        title={
          <>
            IOC in. <span className="text-accent">OSINT</span> out.
          </>
        }
      />
    ),
  },
  { path: '/lookup', label: 'Lookup', size: 'default', el: <LookupRedirect />, nav: false },
  // The omnibox on `/` already classifies a pasted command and docks the same
  // analyzer result inline (ResultRegion.tsx) — Lookup's twin. Kept nav:false
  // rather than deleted: the route stays deep-linkable + full-width for a
  // heavy paste (the inline result's "Expand ->" link targets it).
  { path: '/analyzer', label: 'Analyzer', size: 'default', el: <PowerShellAnalyzer />, nav: false },
  { path: '/desk', label: 'Desk', size: 'default', el: <DataDeskRoute /> },
  { path: '/actor', label: 'Adversaries', size: 'default', el: <ActorProfileRoute /> },
  { path: '/gallery', label: 'Gallery', size: 'default', el: <Gallery />, nav: false },
  { path: '/reports', label: 'My reports', size: 'default', el: <MyReports />, nav: false },
  { path: '/admin', label: 'Admin', size: 'default', el: <Admin />, nav: false },
  { path: '/privacy', label: 'Privacy', size: 'default', el: <Privacy />, nav: false },
  { path: '/about', label: 'About', size: 'default', el: <About />, nav: false },
]

function useRoute(): string {
  const [path, setPath] = useState(() => window.location.pathname)
  useEffect(() => {
    const onPop = () => setPath(window.location.pathname)
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])
  return path
}

function App() {
  const path = useRoute()
  const norm = path.replace(/\/+$/, '') || '/'
  const active =
    ROUTES.find((r) => r.path !== '/' && norm.endsWith(r.path)) ?? ROUTES[0]

  const items = ROUTES.filter((r) => r.nav !== false).map((r) => ({
    label: r.label,
    href: r.path,
    active: r.path === active.path,
  }))

  return (
    <Shell items={items} containerSize={active.size}>
      {active.el}
    </Shell>
  )
}

export default App
