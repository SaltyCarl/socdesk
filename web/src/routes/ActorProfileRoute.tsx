import { useEffect, useMemo, useState } from 'react'
import { MicroLabel } from '../components/ui'
import { ViewHeader } from '../components/views/ViewFrame'
import { AsyncGate, SkeletonRows, EmptyState } from '../components/views/states'
import { ActorProfile } from '../components/views/ActorProfile'
import { ProfileDirectory } from '../components/views/ProfileDirectory'
import { buildProfileIndex, profileFor } from '../components/views/profiles'
import { useStateData, type AsyncStatus } from '../components/views/useStateData'
import { rel } from '../components/views/format'
import { navigate } from '../components/palette/commands'
import type {
  FeedPayload,
  ProfilePayload,
  RansomIntelPayload,
  RelationsPayload,
} from '../components/views/types'

/**
 * /actor — the URL-addressable profile system.
 *
 *   /actor              → the searchable profile DIRECTORY
 *   /actor#g=<slug>     → one fused PROFILE card (slug = lowercased name)
 *
 * The slug rides the hash (a parallel surface deep-links feed entities to it).
 * We read it on `hashchange` AND `popstate`: same-route navigation goes through
 * commands.ts::navigate (pushState + a synthetic popstate), which does NOT emit
 * hashchange, so popstate is what carries a directory→profile click; hashchange
 * covers a raw hash edit / palette hash target. The four snapshots load
 * independently — relations is not gated on (the related panel fills in late).
 */

/** Parse the `g=<slug>` hash param. Empty string → render the directory. */
function readSlug(): string {
  const h = window.location.hash.replace(/^#/, '')
  const m = h.match(/(?:^|&)g=([^&]*)/)
  if (!m) return ''
  try {
    return decodeURIComponent(m[1]).trim().toLowerCase()
  } catch {
    return m[1].trim().toLowerCase()
  }
}

export function ActorProfileRoute() {
  const actors = useStateData<ProfilePayload>('actors')
  const malware = useStateData<ProfilePayload>('malware')
  const feed = useStateData<FeedPayload>('feed')
  const relations = useStateData<RelationsPayload>('relations')
  const intel = useStateData<RansomIntelPayload>('ransomware_intel')

  const [slug, setSlug] = useState<string>(readSlug)
  useEffect(() => {
    const onChange = () => setSlug(readSlug())
    window.addEventListener('hashchange', onChange)
    window.addEventListener('popstate', onChange)
    return () => {
      window.removeEventListener('hashchange', onChange)
      window.removeEventListener('popstate', onChange)
    }
  }, [])

  // Stable refs so the fusion memos below don't recompute every render (a bare
  // `?? []` makes a fresh array each pass and defeats the memo).
  const actorList = useMemo(() => actors.data?.profiles ?? [], [actors.data])
  const malwareList = useMemo(() => malware.data?.profiles ?? [], [malware.data])
  const feedItems = useMemo(() => feed.data?.items ?? [], [feed.data])
  const intelList = useMemo(() => intel.data?.groups ?? [], [intel.data])

  const index = useMemo(
    () => buildProfileIndex(actorList, malwareList, feedItems, intelList),
    [actorList, malwareList, feedItems, intelList],
  )
  const slugSet = useMemo(() => new Set(index.map((e) => e.slug)), [index])

  const profile = useMemo(
    () =>
      slug
        ? profileFor(slug, {
            actors: actorList,
            malware: malwareList,
            feed: feedItems,
            relations: relations.data,
            intel: intelList,
          })
        : null,
    [slug, actorList, malwareList, feedItems, relations.data, intelList],
  )

  const loading =
    actors.status === 'loading' || malware.status === 'loading' || feed.status === 'loading'
  const errored =
    actors.status === 'error' && malware.status === 'error' && feed.status === 'error'
  const status: AsyncStatus = loading ? 'loading' : errored ? 'error' : 'ready'

  const hasData = Boolean(
    profile &&
      (profile.fingerprint ||
        profile.ransomware ||
        profile.reporting.length ||
        profile.related.length ||
        profile.intel ||
        profile.claimedVictims.length ||
        profile.activity),
  )

  const backToDirectory = (e: React.MouseEvent) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
    e.preventDefault()
    navigate('/actor')
  }

  return (
    <div className="flex flex-col gap-6">
      <ViewHeader
        eyebrow="Adversaries"
        kicker={slug ? 'Threat profile' : undefined}
        title={slug ? profile?.name || 'Threat profile' : 'Adversaries'}
        intro={
          slug
            ? 'A single entity, aggregated from ATT&CK, leak-site activity, and open-source reporting — each fact attributed to its source, nothing synthesised.'
            : 'Search and open a profile for any tracked actor, ransomware group, or malware family. Ransomware groups surface their live leak-site claim tally.'
        }
        aside={
          feed.status === 'ready' && feed.data ? (
            <MicroLabel tone="faint">updated {rel(feed.data.generated_at)}</MicroLabel>
          ) : null
        }
      />

      {slug && (
        <a
          href="/actor"
          onClick={backToDirectory}
          className="-mt-2 inline-flex w-fit items-center gap-1 font-mono text-micro font-semibold uppercase tracking-label text-accent underline-offset-2 outline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-accent"
        >
          <span aria-hidden="true">←</span> Adversaries
        </a>
      )}

      <AsyncGate
        status={status}
        label="the threat profiles"
        detail={actors.error ?? malware.error ?? feed.error}
        skeleton={<SkeletonRows rows={8} />}
      >
        {slug ? (
          hasData && profile ? (
            <ActorProfile profile={profile} slugSet={slugSet} />
          ) : (
            <EmptyState title={`No profile on file for “${slug}”`}>
              Nothing in the current snapshot matches this name, alias, or ATT&amp;CK id. It may not
              be a tracked entity yet, or the link may be stale. Use the directory to browse what is
              on file.
            </EmptyState>
          )
        ) : (
          <ProfileDirectory entries={index} />
        )}
      </AsyncGate>
    </div>
  )
}
