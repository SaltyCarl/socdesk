import { useRef, type ReactNode } from 'react'
import { cx } from '../lib/cx'
import { enter, enterStagger } from '../lib/motion'
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  Chip,
  Divider,
  MicroLabel,
  Panel,
  type ChipVariant,
} from '../components/ui'

/* ================================================================== *
 * Layout helpers (internal — not exported, so react-refresh is happy).
 * ================================================================== */

function Section({
  id,
  eyebrow,
  title,
  intro,
  children,
}: {
  id: string
  eyebrow: string
  title: string
  intro?: string
  children: ReactNode
}) {
  return (
    <section id={id} className="scroll-mt-20 py-10">
      <div className="flex flex-col gap-2">
        <MicroLabel tone="accent" tick>
          {eyebrow}
        </MicroLabel>
        <h2 className="font-display text-xl font-extrabold tracking-tight text-paper">
          {title}
        </h2>
        {intro && <p className="max-w-2xl text-base text-muted">{intro}</p>}
      </div>
      <div className="mt-6">{children}</div>
      <Divider className="mt-10" />
    </section>
  )
}

function Label({ children }: { children: ReactNode }) {
  return <MicroLabel className="mb-3">{children}</MicroLabel>
}

/* ================================================================== *
 * Colour
 * ================================================================== */

function Swatch({
  swatch,
  name,
  light,
  dark,
}: {
  swatch: string
  name: string
  light: string
  dark: string
}) {
  return (
    <div className="flex flex-col gap-2">
      <div className={cx('h-14 rounded-md border border-line', swatch)} />
      <div className="flex flex-col gap-0.5">
        <span className="font-mono text-xs font-semibold text-paper">{name}</span>
        <span className="font-mono text-micro text-faint">L {light}</span>
        <span className="font-mono text-micro text-faint">D {dark}</span>
      </div>
    </div>
  )
}

const ROOM: Array<[string, string, string, string]> = [
  ['bg-ink', '--ink', '#F2E6D0', '#15100A'],
  ['bg-panel', '--panel', '#FBF4E6', '#1E1710'],
  ['bg-panel-soft', '--panel-soft', '#F0E2C9', '#2A2015'],
  ['bg-raised', '--raised', '#FDF8EE', '#241A10'],
  ['bg-field', '--field', '#FDF8EE', '#120D07'],
  ['bg-line', '--line', '#DFC9A2', '#34281B'],
  ['bg-line-bright', '--line-bright', '#CDB183', '#473721'],
  ['bg-line-strong', '--line-strong', '#B8975F', '#5E4829'],
]
const TEXT: Array<[string, string, string, string]> = [
  ['bg-paper', '--paper', '#2C2013', '#F1E8D8'],
  ['bg-muted', '--muted', '#6A5638', '#B7A488'],
  ['bg-faint', '--faint', '#98835D', '#877253'],
]
const PRODUCT: Array<[string, string, string, string]> = [
  ['bg-accent', '--accent', '#4A4FD0', '#7C8AFF'],
  ['bg-accent-dim', '--accent-dim', '#6E74E0', '#ADB6FF'],
]
const VERDICT: Array<[string, string, string, string]> = [
  ['bg-verdict-red', '--red', '#D33A50', '#F5566B'],
  ['bg-verdict-amber', '--gold', '#B4740C', '#F2A81E'],
  ['bg-verdict-green', '--green', '#1E9E57', '#4FC97A'],
]

function SwatchGrid({ items }: { items: Array<[string, string, string, string]> }) {
  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
      {items.map(([swatch, name, light, dark]) => (
        <Swatch key={name} swatch={swatch} name={name} light={light} dark={dark} />
      ))}
    </div>
  )
}

/* ================================================================== *
 * Type scale
 * ================================================================== */

const TYPE: Array<[string, string, string]> = [
  ['text-display', 'IOC in. OSINT out.', '64 / 66 · display'],
  ['text-2xl', 'Escalation-ready', '46 / 50 · page title'],
  ['text-xl', 'Section heading', '34 / 40 · section'],
  ['text-lg', 'Card title', '26 / 32 · subhead'],
  ['text-md', 'Lead paragraph', '20 / 28 · lead'],
  ['text-base', 'Body copy — the workhorse reading size.', '16 / 24 · body'],
  ['text-xs', 'Dense data & captions', '13 / 18 · caption'],
]

function TypeRow({ cls, sample, meta }: { cls: string; sample: string; meta: string }) {
  const display = cls === 'text-display' || cls === 'text-2xl' || cls === 'text-xl'
  return (
    <div className="flex flex-col gap-1 border-b border-line py-4 last:border-0 sm:flex-row sm:items-baseline sm:gap-6">
      <span className="w-40 shrink-0 font-mono text-micro text-faint">{meta}</span>
      <span
        className={cx(
          'truncate text-paper',
          cls,
          display ? 'font-display font-extrabold tracking-tight' : 'font-sans',
        )}
      >
        {sample}
      </span>
    </div>
  )
}

/* ================================================================== *
 * Spacing / radii / elevation
 * ================================================================== */

const SPACE: Array<[string, string]> = [
  ['w-1', '1 · 4px'],
  ['w-2', '2 · 8px'],
  ['w-3', '3 · 12px'],
  ['w-4', '4 · 16px'],
  ['w-6', '6 · 24px'],
  ['w-8', '8 · 32px'],
  ['w-12', '12 · 48px'],
]

const RADII: Array<[string, string]> = [
  ['rounded-sm', 'sm · 4px'],
  ['rounded-md', 'md · 8px'],
  ['rounded-lg', 'lg · 12px'],
]

const ELEV: Array<[string, string]> = [
  ['shadow-e0', 'e0 · flat'],
  ['shadow-e1', 'e1 · raised'],
  ['shadow-e2', 'e2 · overlay'],
  ['shadow-e3', 'e3 · modal'],
]

/* ================================================================== *
 * Motion demos
 * ================================================================== */

function MotionDemos() {
  const enterRef = useRef<HTMLDivElement>(null)
  const staggerRef = useRef<HTMLDivElement>(null)

  const playEnter = () => {
    if (enterRef.current) enter(enterRef.current, { y: 12 })
  }
  const playStagger = () => {
    const nodes = staggerRef.current?.querySelectorAll('[data-stagger]')
    if (nodes && nodes.length) enterStagger(nodes)
  }

  return (
    <div className="grid gap-6 sm:grid-cols-2">
      <Panel>
        <Label>enter() · WAAPI fade + rise</Label>
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="sm" onClick={playEnter}>
            Replay
          </Button>
          <div
            ref={enterRef}
            className="rounded-md border border-line bg-field px-4 py-3 font-mono text-xs text-muted"
          >
            opacity + translateY
          </div>
        </div>
      </Panel>

      <Panel>
        <Label>enterStagger() · 60ms cascade</Label>
        <div className="flex flex-col gap-3">
          <Button variant="ghost" size="sm" onClick={playStagger}>
            Replay
          </Button>
          <div ref={staggerRef} className="flex flex-wrap gap-2">
            {['catalog', 'behavioral', 'reputation', 'list'].map((v) => (
              <span key={v} data-stagger>
                <Chip variant={v as ChipVariant} />
              </span>
            ))}
          </div>
        </div>
      </Panel>
    </div>
  )
}

const MOTION_TOKENS: Array<[string, string, string]> = [
  ['--duration-fast', '150ms', 'taps · hover feedback'],
  ['--duration-base', '240ms', 'exits · small moves'],
  ['--duration-slow', '600ms', 'enters · load choreography'],
  ['--duration-draw', '1100ms', 'stroke-on draws'],
  ['--ease-brand', 'cubic-bezier(.16,1,.3,1)', 'expo-out · most enters'],
  ['--ease-brand-io', 'cubic-bezier(.65,0,.35,1)', 'in-out · moves/reorders'],
  ['--ease-spring', 'linear(…)', 'CSS spring approximation'],
]

const MOTION_GUIDE: Array<[string, string]> = [
  ['CSS @keyframes + delay', 'one-shot load choreography (sd-rise). Zero JS.'],
  ['CSS scroll-driven (animation-timeline)', 'scroll reveals / hero melt (sd-reveal). Static fallback.'],
  ['Motion animate() — WAAPI', 'discrete enter/exit, list staggers, toasts.'],
  ['Motion springs', 'input-driven micro-interactions: press/hover scale, pill morph.'],
]

/* ================================================================== *
 * Nested both-theme preview
 * ================================================================== */

function MiniPreview() {
  return (
    <div className="flex flex-col gap-4 bg-ink p-5 text-paper">
      <div className="flex items-center justify-between">
        <MicroLabel tone="accent" tick>
          Escalation
        </MicroLabel>
        <Chip variant="malicious" />
      </div>
      <p className="font-display text-lg font-extrabold tracking-tight text-paper">
        185.220.101.4
      </p>
      <div className="flex flex-wrap gap-2">
        <Chip variant="catalog" />
        <Chip variant="behavioral" />
        <Chip variant="reputation" />
      </div>
      <div className="flex items-center gap-2">
        <Button variant="primary" size="sm">
          Escalate
        </Button>
        <Button variant="ghost" size="sm">
          Copy card
        </Button>
      </div>
    </div>
  )
}

function ThemeFrame({
  theme,
  label,
}: {
  theme: 'light' | 'dark'
  label: string
}) {
  return (
    <div
      data-theme={theme}
      className="overflow-hidden rounded-lg border border-line"
    >
      <div className="border-b border-line bg-panel px-4 py-2">
        <MicroLabel>{label}</MicroLabel>
      </div>
      <MiniPreview />
    </div>
  )
}

/* ================================================================== *
 * Gallery
 * ================================================================== */

export function Gallery() {
  return (
    <div>
      {/* page intro */}
      <header className="border-b border-line pb-10">
        <MicroLabel tone="accent" tick>
          Design system
        </MicroLabel>
        <h1 className="mt-3 font-display text-2xl font-extrabold tracking-display text-paper">
          SOCDesk primitives &amp; tokens
        </h1>
        <p className="mt-3 max-w-2xl text-md text-muted">
          Warm-espresso dark + warm-paper light, one periwinkle accent,
          verdict red/amber/green reserved for meaning. Toggle the theme in
          the topbar — every surface below re-paints from the same tokens.
        </p>
      </header>

      <Section
        id="colour"
        eyebrow="Tokens"
        title="Colour"
        intro="The room is warm neutral; the product is periwinkle; red/amber/green are verdict-only and never decorative. Hexes are the source-of-truth values shared with the live site and the copy-card PNG."
      >
        <div className="flex flex-col gap-8">
          <div>
            <Label>Room · neutrals</Label>
            <SwatchGrid items={ROOM} />
          </div>
          <div>
            <Label>Text</Label>
            <SwatchGrid items={TEXT} />
          </div>
          <div>
            <Label>Product · periwinkle accent</Label>
            <SwatchGrid items={PRODUCT} />
          </div>
          <div>
            <Label>Verdict · severity (reserved)</Label>
            <SwatchGrid items={VERDICT} />
          </div>
        </div>
      </Section>

      <Section
        id="type"
        eyebrow="Tokens"
        title="Type scale"
        intro="A coarse ramp — 7 perceptible steps + a display size, integer pixels only. Archivo for display, IBM Plex Mono for data and micro-labels; figures are tabular everywhere."
      >
        <div className="flex flex-col">
          {TYPE.map(([cls, sample, meta]) => (
            <TypeRow key={cls} cls={cls} sample={sample} meta={meta} />
          ))}
        </div>
      </Section>

      <Section
        id="scale"
        eyebrow="Tokens"
        title="Spacing · radii · elevation"
        intro="A 4/8 spacing grid, three concentric radii (4/8/12), and a four-step elevation scale tinted by the per-theme shadow ink. Chrome stays recessive — e2/e3 are for overlays."
      >
        <div className="grid gap-8 lg:grid-cols-3">
          <div>
            <Label>Spacing · 4 / 8 grid</Label>
            <div className="flex flex-col gap-2">
              {SPACE.map(([w, meta]) => (
                <div key={w} className="flex items-center gap-3">
                  <div className={cx('h-4 rounded-sm bg-accent', w)} />
                  <span className="font-mono text-micro text-faint">{meta}</span>
                </div>
              ))}
            </div>
          </div>
          <div>
            <Label>Radii · 4 / 8 / 12</Label>
            <div className="flex flex-wrap gap-4">
              {RADII.map(([r, meta]) => (
                <div key={r} className="flex flex-col items-center gap-2">
                  <div className={cx('size-16 border border-line-bright bg-panel-soft', r)} />
                  <span className="font-mono text-micro text-faint">{meta}</span>
                </div>
              ))}
            </div>
          </div>
          <div>
            <Label>Elevation</Label>
            <div className="flex flex-wrap gap-4">
              {ELEV.map(([s, meta]) => (
                <div key={s} className="flex flex-col items-center gap-2">
                  <div className={cx('size-16 rounded-md border border-line bg-raised', s)} />
                  <span className="font-mono text-micro text-faint">{meta}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Section>

      <Section
        id="buttons"
        eyebrow="Primitives"
        title="Buttons"
        intro="Primary is the one loud CTA (filled periwinkle). Ghost is the hairline workhorse. Danger is a quiet tinted red for destructive actions only — meaning-bearing, never a decorative fill. Press for the spring scale."
      >
        <div className="flex flex-col gap-6">
          <div className="flex flex-wrap items-center gap-3">
            <Button variant="primary">Escalate</Button>
            <Button variant="ghost">Copy card</Button>
            <Button variant="danger">Purge cache</Button>
            <Button variant="primary" disabled>
              Disabled
            </Button>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button variant="primary" size="sm">
              Escalate
            </Button>
            <Button variant="ghost" size="sm">
              Copy card
            </Button>
            <Button variant="danger" size="sm">
              Purge cache
            </Button>
          </div>
        </div>
      </Section>

      <Section
        id="chips"
        eyebrow="Primitives"
        title="Chips &amp; badges"
        intro="Verdict-severity chips are the only place red/amber/green appear (color + word + dot, a redundant encoding). Grayware is a distinct amber — flagged, not confirmed malware. Unknown is grey, never green. Source-class chips are facts about a source, ranked by ink weight — periwinkle/neutral, never a verdict hue."
      >
        <div className="flex flex-col gap-6">
          <div>
            <Label>Verdict · severity</Label>
            <div className="flex flex-wrap gap-2">
              <Chip variant="malicious" />
              <Chip variant="suspicious" />
              <Chip variant="grayware" />
              <Chip variant="benign" />
              <Chip variant="unknown" />
            </div>
          </div>
          <div>
            <Label>Source-class · catalog</Label>
            <div className="flex flex-wrap gap-2">
              <Chip variant="catalog" />
              <Chip variant="behavioral" />
              <Chip variant="reputation" />
              <Chip variant="list" />
            </div>
          </div>
          <div>
            <Label>General · neutral / accent / pill</Label>
            <div className="flex flex-wrap gap-2">
              <Chip variant="neutral">SHA-256</Chip>
              <Chip variant="accent">KEV</Chip>
              <Chip variant="accent" pill>
                4 / 12 sources
              </Chip>
            </div>
          </div>
        </div>
      </Section>

      <Section
        id="surfaces"
        eyebrow="Primitives"
        title="Surfaces"
        intro="Panel is the recessive flat work surface; Card is a lifted surface with e1 elevation (interactive cards raise to e2 on hover). Both are hairline-bordered at radius-lg."
      >
        <div className="grid gap-6 md:grid-cols-3">
          <Panel>
            <MicroLabel tone="accent">Panel</MicroLabel>
            <p className="mt-2 text-base text-muted">
              Flat --panel, no shadow. The default dense container.
            </p>
          </Panel>
          <Card>
            <CardHeader eyebrow="Card" title="Elevated surface" />
            <CardBody className="mt-3">
              --raised with e1. Reserve elevation for things that float.
            </CardBody>
          </Card>
          <Card interactive>
            <CardHeader
              eyebrow="Interactive"
              title="Hover me"
              aside={<Chip variant="benign" />}
            />
            <CardBody className="mt-3">
              Border brightens and elevation lifts to e2 on hover.
            </CardBody>
          </Card>
        </div>
      </Section>

      <Section
        id="misc"
        eyebrow="Primitives"
        title="Micro-labels · dividers · focus"
        intro="The shared micro-label token (mono, 11px floor, wide tracking, uppercase) in its three tones, hairline dividers, and the visible AA focus ring (tab to the field to see the crisp 2px offset — never a bloom)."
      >
        <div className="grid gap-6 md:grid-cols-3">
          <Panel>
            <Label>Micro-label tones</Label>
            <div className="flex flex-col gap-3">
              <MicroLabel tone="accent" tick>
                Threat intelligence
              </MicroLabel>
              <MicroLabel tone="muted">Last seen 4m ago</MicroLabel>
              <MicroLabel tone="faint">List membership</MicroLabel>
            </div>
          </Panel>
          <Panel>
            <Label>Dividers</Label>
            <div className="flex flex-col gap-4">
              <Divider />
              <Divider strong />
              <div className="flex h-8 items-center gap-4">
                <span className="font-mono text-xs text-muted">A</span>
                <Divider orientation="vertical" />
                <span className="font-mono text-xs text-muted">B</span>
              </div>
            </div>
          </Panel>
          <Panel>
            <Label>Focus ring · AA</Label>
            <input
              type="text"
              placeholder="Tab to focus me"
              className="w-full rounded-md border border-line bg-field px-3 py-2 font-mono text-base text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
            />
          </Panel>
        </div>
      </Section>

      <Section
        id="motion"
        eyebrow="Language"
        title="Motion"
        intro="Discrete transitions run on WAAPI; input-driven micro-interactions use Motion.dev springs; load and scroll choreography stay in CSS. Everything honours prefers-reduced-motion. All CSP-safe — no injected styles."
      >
        <div className="flex flex-col gap-8">
          <MotionDemos />
          <Panel>
            <Label>Scroll-driven · animation-timeline (progressive enhancement)</Label>
            <p className="mb-3 max-w-2xl text-base text-muted">
              The <code className="font-mono text-xs text-accent">.sd-reveal</code>{' '}
              hook fades + rises a block as it enters the viewport —
              compositor-threaded, zero JS, CSP-perfect — with a static
              fallback for unsupported browsers and reduced motion. This is
              the documented setup for later scroll choreography (hero melt,
              sticky timelines). Scroll it into view:
            </p>
            <div className="sd-reveal rounded-md border border-line bg-field px-4 py-3 font-mono text-xs text-muted">
              .sd-reveal · reveals on scroll (visible by default everywhere it
              can&apos;t enhance)
            </div>
          </Panel>
          <div className="grid gap-6 lg:grid-cols-2">
            <div>
              <Label>Motion tokens</Label>
              <div className="overflow-hidden rounded-lg border border-line">
                {MOTION_TOKENS.map(([name, val, use], i) => (
                  <div
                    key={name}
                    className={cx(
                      'grid grid-cols-[10rem_1fr] gap-3 bg-panel px-4 py-2.5',
                      i > 0 && 'border-t border-line',
                    )}
                  >
                    <span className="font-mono text-micro font-semibold text-accent">
                      {name}
                    </span>
                    <span className="flex flex-col">
                      <span className="font-mono text-xs text-paper">{val}</span>
                      <span className="font-mono text-micro text-faint">{use}</span>
                    </span>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <Label>When to use which</Label>
              <div className="flex flex-col gap-2">
                {MOTION_GUIDE.map(([mech, use]) => (
                  <div
                    key={mech}
                    className="rounded-md border border-line bg-panel px-4 py-3"
                  >
                    <div className="font-mono text-xs font-semibold text-paper">
                      {mech}
                    </div>
                    <div className="mt-0.5 text-base text-muted">{use}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </Section>

      <Section
        id="themes"
        eyebrow="Review"
        title="Both themes, one page"
        intro="The same primitives rendered in a forced-light and a forced-dark scope side by side (nested [data-theme]), independent of the global toggle."
      >
        <div className="grid gap-6 md:grid-cols-2">
          <ThemeFrame theme="light" label="Warm paper · light" />
          <ThemeFrame theme="dark" label="Espresso · dark" />
        </div>
      </Section>
    </div>
  )
}
