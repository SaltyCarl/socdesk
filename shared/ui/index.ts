/** SOCDesk shared UI primitives — barrel export.
 *  Framework-agnostic building blocks consumed by BOTH the web app and the
 *  browser extension. Web-only chrome (Topbar/AppShell/ThemeToggle) is NOT
 *  here — it stays local to web/src/components/ui. */
export { Button } from './Button'
export type { ButtonProps } from './Button'
export { buttonClasses } from './buttonClasses'
export type { ButtonSize, ButtonVariant } from './buttonClasses'
export { Card, CardBody, CardHeader, Panel } from './Card'
export type { SurfacePadding } from './Card'
export { Chip } from './Chip'
export type { ChipVariant } from './Chip'
export { Divider } from './Divider'
export { MicroLabel } from './MicroLabel'
export type { MicroLabelTone } from './MicroLabel'
