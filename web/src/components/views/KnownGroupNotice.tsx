import { ExternalLink } from './ExternalLink'
import { EmptyState } from './states'

/**
 * The honest state for a NAME-ONLY coverage-layer group (ransomware_groups.json):
 * the slug is a real ransomware.live-tracked group, but SOCDesk holds nothing on
 * it — no claims in the current window, no ATT&CK fingerprint, no curated intel.
 * Distinct from the unknown-slug "No profile on file" state: this one says the
 * group IS tracked and links OUT to the upstream page (R3: name + link only,
 * no editorial mirrored).
 */
export function KnownGroupNotice({ slug, name }: { slug: string; name?: string }) {
  const href = `https://www.ransomware.live/group/${encodeURIComponent(slug)}`
  return (
    <EmptyState title={`${name || slug} is tracked, with nothing on file yet`}>
      This ransomware group is on ransomware.live&rsquo;s tracked list, but SOCDesk holds no
      claims in the current window, no ATT&amp;CK fingerprint, and no curated intel for it —
      so there is no profile to render. The upstream tracker may hold more.{' '}
      <ExternalLink href={href}>View at ransomware.live</ExternalLink>
    </EmptyState>
  )
}
