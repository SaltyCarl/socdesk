import { useDeferredValue, useMemo, useState } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import type { KindedProfile, Profile } from './types'
import { num } from './format'
import {
  buildRelationsIndex,
  provenance,
  relatedFor,
  PIVOTABLE,
  techniqueUrl,
  type RelationsIndex,
} from './relations'
import type { RelationsPayload } from './types'
import { MonoTag } from './Badges'
import { CountUp } from './CountUp'
import { EmptyState } from './states'

/**
 * Actor & malware profiles from ATT&CK. The differentiator is the RELATED
 * panel — the one sanctioned view of relations.json (a ranked list keyed to
 * the entity in focus, not a node-link graph, per docs/RELATIONSHIPS.md).
 * Live feed co-occurrence outranks encyclopedia structure, so the panel leads
 * with what's actually been reported together.
 */

const INIT = 30
const STEP = 60

function attackUrl(kind: 'actor' | 'malware', id?: string): string {
  if (!id) return ''
  return kind === 'actor'
    ? `https://attack.mitre.org/groups/${encodeURIComponent(id)}/`
    : `https://attack.mitre.org/software/${encodeURIComponent(id)}/`
}

/** Strip ATT&CK markdown noise so the description reads as prose. */
function cleanDescription(d?: string): string {
  return (d ?? '')
    .replace(/\(Citation:[^)]*\)/g, '')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/\s{2,}/g, ' ')
    .trim()
}

/* ---------------- profile card ---------------- */

function ProfileCard({
  profile,
  active,
  onClick,
}: {
  profile: KindedProfile
  active: boolean
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cx(
        'sd-reveal flex flex-col items-start gap-2 rounded-lg border bg-panel p-4 text-left transition-colors duration-150 ease-brand',
        'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent',
        active
          ? 'border-[var(--edge-accent)] bg-[var(--tint-accent)]'
          : 'border-line hover:border-line-bright hover:bg-panel-soft',
      )}
    >
      <div className="flex w-full items-center justify-between gap-2">
        <MonoTag tone={profile.kind === 'actor' ? 'accent' : 'muted'}>
          {profile.kind}
        </MonoTag>
        <span className="font-mono text-micro text-faint">
          {profile.attack_id}
        </span>
      </div>
      <span className="font-display text-base font-bold tracking-tight text-paper">
        {profile.name}
      </span>
      <span className="line-clamp-1 font-mono text-micro text-muted">
        {(profile.aliases ?? []).slice(0, 3).join(' · ') || '—'}
      </span>
      <span className="mt-1 flex gap-3 font-mono text-micro text-faint">
        <span>{num(profile.techniques?.length ?? 0)} techniques</span>
        <span>{num(profile.software?.length ?? 0)} software</span>
      </span>
    </button>
  )
}

/* ---------------- related panel ---------------- */

function RelatedPanel({
  index,
  profile,
  onPivot,
}: {
  index: RelationsIndex
  profile: KindedProfile
  onPivot: (name: string) => void
}) {
  const rows = useMemo(
    () => relatedFor(index, [profile.name, ...(profile.aliases ?? [])]),
    [index, profile],
  )
  if (!rows.length) {
    return (
      <p className="text-xs text-muted">
        No related entities recorded — this profile has no ATT&amp;CK links or
        feed co-occurrences in the current snapshot.
      </p>
    )
  }
  return (
    <div className="flex flex-col divide-y divide-line">
      {rows.map(({ node, edge }) => {
        const pivotable = PIVOTABLE.has(node.type)
        return (
          <div
            key={node.id}
            className="flex items-center justify-between gap-3 py-2"
          >
            <span className="flex min-w-0 items-center gap-2">
              <MonoTag tone="faint">{node.type}</MonoTag>
              {pivotable ? (
                <button
                  type="button"
                  onClick={() => onPivot(node.name)}
                  className="truncate text-xs font-semibold text-paper underline-offset-2 hover:text-accent hover:underline"
                >
                  {node.name}
                </button>
              ) : node.type === 'technique' ? (
                <a
                  href={techniqueUrl(node.name)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="truncate text-xs text-accent underline-offset-2 hover:underline"
                >
                  {node.name} ↗
                </a>
              ) : (
                <span className="truncate text-xs text-muted">{node.name}</span>
              )}
            </span>
            <span className="whitespace-nowrap font-mono text-micro text-faint">
              {provenance(edge.evidence)} · w{edge.weight}
            </span>
          </div>
        )
      })}
    </div>
  )
}

/* ---------------- detail ---------------- */

function TagLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="rounded-sm border border-line bg-panel-soft px-1.5 py-0.5 font-mono text-micro text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-accent"
    >
      {children}
    </a>
  )
}

function Detail({
  index,
  profile,
  onPivot,
}: {
  index: RelationsIndex
  profile: KindedProfile
  onPivot: (name: string) => void
}) {
  const url = attackUrl(profile.kind, profile.attack_id)
  const desc = cleanDescription(profile.description)
  return (
    <div className="flex flex-col gap-5 rounded-lg border border-line bg-raised p-5 shadow-e1">
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between gap-2">
          <MonoTag tone={profile.kind === 'actor' ? 'accent' : 'muted'}>
            {profile.kind}
          </MonoTag>
          {url && (
            <a
              href={url}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-micro text-accent underline-offset-2 hover:underline"
            >
              {profile.attack_id} ↗
            </a>
          )}
        </div>
        <h2 className="font-display text-lg font-extrabold tracking-tight text-paper">
          {profile.name}
        </h2>
        {(profile.aliases ?? []).length > 0 && (
          <p className="font-mono text-micro text-muted">
            {(profile.aliases ?? []).join(' · ')}
          </p>
        )}
      </div>

      {desc && <p className="text-xs leading-relaxed text-muted">{desc}</p>}

      {(profile.techniques ?? []).length > 0 && (
        <div className="flex flex-col gap-2">
          <span className="font-mono text-micro uppercase tracking-label text-faint">
            Techniques · {num(profile.techniques?.length ?? 0)}
          </span>
          <div className="flex flex-wrap gap-1.5">
            {(profile.techniques ?? []).map((t) => (
              <TagLink key={t} href={techniqueUrl(t)}>
                {t}
              </TagLink>
            ))}
          </div>
        </div>
      )}

      {(profile.software ?? []).length > 0 && (
        <div className="flex flex-col gap-2">
          <span className="font-mono text-micro uppercase tracking-label text-faint">
            Software · {num(profile.software?.length ?? 0)}
          </span>
          <div className="flex flex-wrap gap-1.5">
            {(profile.software ?? []).map((s) => (
              <span
                key={s}
                className="rounded-sm border border-line bg-panel-soft px-1.5 py-0.5 font-mono text-micro text-muted"
              >
                {s}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="flex flex-col gap-2 border-t border-line pt-4">
        <span className="font-mono text-micro uppercase tracking-label text-accent">
          Related entities
        </span>
        <RelatedPanel index={index} profile={profile} onPivot={onPivot} />
      </div>
    </div>
  )
}

/* ---------------- view ---------------- */

export function ActorsView({
  actors,
  malware,
  relations,
}: {
  actors: Profile[]
  malware: Profile[]
  relations: RelationsPayload | null
}) {
  const [rawQuery, setRawQuery] = useState('')
  const query = useDeferredValue(rawQuery)
  const [limit, setLimit] = useState(INIT)
  const [selectedName, setSelectedName] = useState<string | null>(null)

  const index = useMemo(() => buildRelationsIndex(relations), [relations])

  const profiles = useMemo<KindedProfile[]>(
    () => [
      ...actors.filter((p) => p.name).map((p) => ({ ...p, kind: 'actor' as const })),
      ...malware.filter((p) => p.name).map((p) => ({ ...p, kind: 'malware' as const })),
    ],
    [actors, malware],
  )

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return profiles
    return profiles.filter((p) =>
      (p.name + ' ' + (p.aliases ?? []).join(' ') + ' ' + (p.attack_id ?? ''))
        .toLowerCase()
        .includes(q),
    )
  }, [profiles, query])

  const shown = filtered.slice(0, limit)

  const selected =
    profiles.find((p) => p.name === selectedName) ?? filtered[0] ?? profiles[0] ?? null

  const pivot = (name: string) => {
    const match = profiles.find((p) => p.name.toLowerCase() === name.toLowerCase())
    if (match) setSelectedName(match.name)
  }

  if (!profiles.length) {
    return (
      <EmptyState title="No ATT&CK profiles published yet">
        The actors collector ships profiles independently of the feed. They
        appear here after the next successful profile pull.
      </EmptyState>
    )
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-center gap-3">
        <input
          type="search"
          value={rawQuery}
          onChange={(e) => {
            setRawQuery(e.target.value)
            setLimit(INIT)
          }}
          placeholder="Search actor / malware, alias, ATT&CK id…"
          aria-label="Search profiles"
          className="h-9 w-full max-w-sm rounded-md border border-line bg-field px-3 font-mono text-base text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
        />
        <span className="ml-auto font-mono text-micro uppercase tracking-label text-faint">
          <CountUp value={filtered.length} /> of <CountUp value={profiles.length} />{' '}
          profiles
        </span>
      </div>

      <div className="grid gap-5 lg:grid-cols-[1fr_360px]">
        {/* master */}
        <div className="flex flex-col gap-4">
          {filtered.length === 0 ? (
            <EmptyState title="No profile matches that search">
              Try a shorter term, an alias, or an ATT&amp;CK id like G0001 —
              the catalog is loaded, this filter just excludes everything.
            </EmptyState>
          ) : (
            <>
              <div className="grid gap-3 sm:grid-cols-2">
                {shown.map((p) => (
                  <ProfileCard
                    key={`${p.kind}:${p.name}`}
                    profile={p}
                    active={selected?.name === p.name}
                    onClick={() => setSelectedName(p.name)}
                  />
                ))}
              </div>
              {filtered.length > limit && (
                <button
                  type="button"
                  onClick={() => setLimit((n) => n + STEP)}
                  className="mx-auto rounded-md border border-line bg-panel px-4 py-2 font-mono text-xs text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent"
                >
                  Load more — {num(filtered.length - shown.length)} remaining
                </button>
              )}
            </>
          )}
        </div>

        {/* detail */}
        <div className="lg:sticky lg:top-20 lg:self-start">
          {selected ? (
            <Detail index={index} profile={selected} onPivot={pivot} />
          ) : (
            <p className="text-xs text-muted">Select a profile to inspect it.</p>
          )}
        </div>
      </div>
    </div>
  )
}
