/** SOCDesk UI barrel.
 *  Primitives are sourced from @socdesk/shared/ui (the framework-agnostic
 *  layer both the web app and the extension consume); the app chrome
 *  (Topbar / AppShell / ThemeToggle / NavItem) stays web-local. */
export {
  Button,
  buttonClasses,
  Card,
  CardBody,
  CardHeader,
  Panel,
  Chip,
  Divider,
  MicroLabel,
} from '@socdesk/shared/ui'
export type {
  ButtonProps,
  ButtonSize,
  ButtonVariant,
  SurfacePadding,
  ChipVariant,
  MicroLabelTone,
} from '@socdesk/shared/ui'
export { ThemeToggle } from './ThemeToggle'
export { AppShell, Topbar } from './Topbar'
export type { NavItem } from './Topbar'
