import { useEffect, useRef, useState } from 'react'
import sequence from './assets/privacy-vault-sequence.png'

const FRAME_COUNT = 20

export function frameForProgress(progress: number, reducedMotion: boolean): number {
  if (reducedMotion || !Number.isFinite(progress)) return 0
  return Math.round(Math.max(0, Math.min(1, progress)) * (FRAME_COUNT - 1))
}

export function scrollProgress(top: number, height: number, viewportHeight: number): number {
  return Math.max(0, Math.min(1, -top / Math.max(1, height - viewportHeight)))
}

export function visibleProgress(top: number, height: number, viewportHeight: number): number {
  const start = viewportHeight * 0.4
  return Math.max(0, Math.min(1, (start - top) / Math.max(1, height + start)))
}

function Fallback() {
  return <svg className="scene-fallback" viewBox="0 0 420 420" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="80" y="80" width="260" height="260" rx="48" fill="#B9E5DB" fillOpacity=".5" stroke="#145F62" strokeWidth="3" /><rect x="155" y="130" width="110" height="155" rx="10" fill="#F0FFF8" fillOpacity=".7" stroke="#145F62" strokeWidth="3" /><path d="M175 170h70M175 195h55M175 220h70M175 245h45" stroke="#145F62" strokeWidth="4" strokeLinecap="round" /></svg>
}

export default function Scene() {
  const container = useRef<HTMLDivElement>(null)
  const [frame, setFrame] = useState(0)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    const hero = container.current?.closest<HTMLElement>('.hero')
    if (!hero) return
    const motion = window.matchMedia?.('(prefers-reduced-motion: reduce)')
    const mobile = window.matchMedia?.('(max-width: 650px)')
    let pending: number | null = null
    const update = () => {
      pending = null
      const bounds = (mobile?.matches ? container.current : hero)?.getBoundingClientRect()
      if (!bounds) return
      const progress = mobile?.matches
        ? visibleProgress(bounds.top, bounds.height, window.innerHeight)
        : scrollProgress(bounds.top, bounds.height, window.innerHeight)
      setFrame(frameForProgress(progress, !!motion?.matches))
    }
    const requestUpdate = () => {
      if (pending === null) pending = window.requestAnimationFrame(update)
    }
    window.addEventListener('scroll', requestUpdate, { passive: true })
    window.addEventListener('resize', requestUpdate)
    motion?.addEventListener?.('change', requestUpdate)
    requestUpdate()
    return () => {
      window.removeEventListener('scroll', requestUpdate)
      window.removeEventListener('resize', requestUpdate)
      motion?.removeEventListener?.('change', requestUpdate)
      if (pending !== null) window.cancelAnimationFrame(pending)
    }
  }, [])

  const column = frame % 5
  const row = Math.floor(frame / 5)
  return <div className="scene" ref={container} aria-hidden="true">
    {failed ? <Fallback /> : <div className="sequence-window"><img src={sequence} alt="" className="sequence-sprite" style={{ transform: `translate(${-column * 20}%, ${-row * 25}%)` }} onError={() => setFailed(true)} /></div>}
  </div>
}
