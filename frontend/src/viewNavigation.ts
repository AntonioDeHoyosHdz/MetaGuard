import type { MouseEvent } from 'react'

export const mainViews = [
  { id: 'home', name: 'Inicio', hash: '#inicio' },
  { id: 'guide', name: 'Cómo funciona', hash: '#como-funciona' },
  { id: 'files', name: 'Archivos y reportes', hash: '#demostracion' },
  { id: 'account', name: 'Cuenta', hash: '#cuenta' },
  { id: 'privacy', name: 'Privacidad', hash: '#privacidad' },
] as const
export type MainView = typeof mainViews[number]['id']
export type View = MainView | 'activity'
export type NavigateToView = (event: MouseEvent<HTMLAnchorElement>, view: View) => void

const activityPath = '/security/events'

export function resolveView({ pathname, hash }: Pick<Location, 'pathname' | 'hash'>): View {
  if (pathname === activityPath) return 'activity'
  return mainViews.find((view) => view.hash === hash)?.id ?? 'home'
}

export function viewHref(view: View): string {
  if (view === 'activity') return `${activityPath}#actividad`
  // Hash URLs load from the static entry point; only the original security URL
  // needs the existing server rewrite.
  return `/${mainViews.find((entry) => entry.id === view)?.hash ?? ''}`
}

export function isPlainAnchorClick(event: MouseEvent<HTMLAnchorElement>): boolean {
  return !event.defaultPrevented && event.button === 0 && !event.metaKey &&
    !event.ctrlKey && !event.shiftKey && !event.altKey
}
