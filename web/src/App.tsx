import { useEffect, useState, type ReactNode } from 'react'
import { Shell, type ContainerSize } from './components/shell'
import { Overview } from './routes/Overview'
import { Lookup } from './routes/Lookup'
import { DataDeskRoute } from './routes/DataDeskRoute'
import { ActorProfileRoute } from './routes/ActorProfileRoute'
import { Gallery } from './routes/Gallery'

/**
 * App router — a tiny pathname read (no router dependency) drives a small
 * suffix→component table. Vite preview / Cloudflare Pages both fall back to
 * index.html, so client routing resolves from any deep link.
 *
 *   /         → the Overview (three.js globe hero + start-of-shift board)
 *   /lookup   → the escalation-card system (IP / domain / URL / hash / CVE)
 *   /desk     → the data desk (feed / vulns / actors / health / sources)
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
}

const ROUTES: Route[] = [
  {
    path: '/',
    label: 'Overview',
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
  { path: '/lookup', label: 'Lookup', size: 'default', el: <Lookup /> },
  { path: '/desk', label: 'Desk', size: 'default', el: <DataDeskRoute /> },
  { path: '/actor', label: 'Profiles', size: 'default', el: <ActorProfileRoute /> },
  { path: '/gallery', label: 'Gallery', size: 'default', el: <Gallery /> },
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

  const items = ROUTES.map((r) => ({
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
