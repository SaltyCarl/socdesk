import { useEffect, useRef, useState } from 'react'
import { AppShell, MicroLabel, buttonClasses } from './components/ui'
import { Gallery } from './routes/Gallery'
import { useEnterOnMount } from './lib/motion'

/**
 * Design-system app. Two routes, one shell:
 *   /          → a minimal overview that links into the gallery
 *   /gallery   → the full token + primitive gallery (the review surface)
 *
 * No router dependency — a tiny pathname read is enough for a static SPA
 * (Vite preview / Cloudflare Pages both fall back to index.html).
 */

function useRoute(): string {
  const [path, setPath] = useState(() => window.location.pathname)
  useEffect(() => {
    const onPop = () => setPath(window.location.pathname)
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])
  return path
}

function Home() {
  const heroRef = useRef<HTMLDivElement>(null)
  useEnterOnMount(heroRef)

  return (
    <div ref={heroRef} className="flex flex-col items-start gap-6 py-16">
      <MicroLabel tone="accent" tick>
        Design system
      </MicroLabel>
      <h1 className="max-w-3xl font-display text-display font-extrabold tracking-display text-paper">
        IOC in. <span className="text-accent">OSINT out.</span>
      </h1>
      <p className="max-w-2xl text-md text-muted">
        The SOCDesk primitive library — warm-espresso and warm-paper themes,
        one periwinkle accent, verdict colours reserved for meaning. Built on
        Vite, React, Tailwind v4 and Motion.dev under a strict CSP.
      </p>
      <a className={buttonClasses('primary', 'md')} href="/gallery">
        Open the gallery
      </a>
    </div>
  )
}

const NAV = [
  { label: 'Overview', href: '/' },
  { label: 'Gallery', href: '/gallery' },
]

function App() {
  const path = useRoute()
  const onGallery = path.replace(/\/+$/, '').endsWith('/gallery')
  const items = NAV.map((n) => ({
    ...n,
    active: n.href === '/gallery' ? onGallery : !onGallery,
  }))

  return (
    <AppShell items={items}>{onGallery ? <Gallery /> : <Home />}</AppShell>
  )
}

export default App
