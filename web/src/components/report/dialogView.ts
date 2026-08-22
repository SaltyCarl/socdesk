import type { SessionState } from '../../lib/useSession'

/** The base (pre-submit) screen, from session status alone. Terminal post-submit
 *  screens are driven by reportOutcome (Task 8), not this. */
export type DialogView = 'loading' | 'gate' | 'fill'

export function dialogView(status: SessionState['status']): DialogView {
  switch (status) {
    case 'loading':
      return 'loading'
    case 'out':
      return 'gate'
    case 'in':
      return 'fill'
  }
}
