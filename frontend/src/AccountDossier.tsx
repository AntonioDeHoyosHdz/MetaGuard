import { AtSign, Crosshair, KeyRound, Layers3, LockKeyhole, MoveVertical, RotateCw, ShieldCheck, UserPlus } from 'lucide-react'
import { useLayoutEffect, useRef, useState, type CSSProperties, type PointerEvent, type ReactNode } from 'react'
import { LivingType } from './PrivacyHero'

export type AccountView = 'login' | 'register' | 'verify'
type AccountFace = AccountView | 'mfa' | 'session'
type Orbit = { x: number; y: number }
type Drag = { id: number; x: number; y: number; start: Orbit; axis: 'both' | 'horizontal' | 'pending' }
const centered: Orbit = { x: 0, y: 0 }

const faces = [
  { id: 'login', icon: KeyRound, label: 'Acceso' },
  { id: 'register', icon: UserPlus, label: 'Registro' },
  { id: 'verify', icon: AtSign, label: 'Correo' },
  { id: 'mfa', icon: LockKeyhole, label: 'Autenticador' },
  { id: 'session', icon: ShieldCheck, label: 'Sesión' },
  { id: 'brand', icon: Layers3, label: 'MetaGuard' },
]

const stages: { id: AccountView; label: string }[] = [
  { id: 'register', label: 'Registro' },
  { id: 'verify', label: 'Verificación' },
  { id: 'login', label: 'Acceso' },
]

function AccessObject({ face }: { face: AccountFace }) {
  const [orbit, setOrbit] = useState(centered)
  const [dragging, setDragging] = useState(false)
  const drag = useRef<Drag | null>(null)

  function reset() {
    drag.current = null
    setDragging(false)
    setOrbit(centered)
  }

  // Keep the cube mounted so changes in the account face can still transition.
  useLayoutEffect(reset, [face])

  function startDrag(event: PointerEvent<HTMLDivElement>) {
    if (!event.isPrimary || event.button !== 0 || drag.current) return
    const axis = event.pointerType === 'touch' ? 'pending' : 'both'
    drag.current = { id: event.pointerId, x: event.clientX, y: event.clientY, start: orbit, axis }
    event.currentTarget.setPointerCapture?.(event.pointerId)
  }

  function moveDrag(event: PointerEvent<HTMLDivElement>) {
    const start = drag.current
    if (start?.id !== event.pointerId) return
    const dx = event.clientX - start.x
    const dy = event.clientY - start.y
    if (!dragging && Math.max(Math.abs(dx), Math.abs(dy)) < 6) return
    if (start.axis === 'pending') {
      if (Math.abs(dy) >= Math.abs(dx)) {
        drag.current = null
        return
      }
      start.axis = 'horizontal'
    }
    setDragging(true)
    setOrbit({
      x: start.axis === 'both' ? Math.max(-70, Math.min(70, start.start.x - dy * .6)) : start.start.x,
      y: start.start.y + dx * .6,
    })
  }

  function finishDrag(event: PointerEvent<HTMLDivElement>) {
    if (drag.current?.id !== event.pointerId) return
    drag.current = null
    setDragging(false)
  }

  const rotation = { '--orbit-x': `${orbit.x}deg`, '--orbit-y': `${orbit.y}deg` } as CSSProperties
  return (
    <div className="access-object">
      <div className="access-orbit" aria-hidden="true"
        onPointerDown={startDrag} onPointerMove={moveDrag}
        onPointerUp={finishDrag} onPointerCancel={finishDrag} onLostPointerCapture={finishDrag}
      >
        <div className="access-cube" data-face={face} data-dragging={dragging || undefined} style={rotation}>
          {faces.map(({ id, icon: Icon, label }) => (
            <div className="access-face" data-panel={id} key={id}>
              <Icon strokeWidth={1.65} />
              <span>{label}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="access-rotation" role="group" aria-label="Orientación del cubo">
        <span aria-hidden="true">Arrastra para girar</span>
        <button type="button" aria-label="Girar el cubo" title="Girar el cubo"
          onClick={() => setOrbit(current => ({ ...current, y: current.y + 45 }))}>
          <RotateCw size={17} aria-hidden="true" />
        </button>
        <button type="button" aria-label="Inclinar el cubo" title="Inclinar el cubo"
          onClick={() => setOrbit(current => ({ ...current, x: current.x >= 45 ? -60 : Math.min(60, current.x + 30) }))}>
          <MoveVertical size={17} aria-hidden="true" />
        </button>
        <button type="button" aria-label="Restablecer orientación del cubo" title="Restablecer orientación del cubo" onClick={reset}>
          <Crosshair size={17} aria-hidden="true" />
        </button>
      </div>
    </div>
  )
}

export default function AccountDossier({ children, face, stage }: {
  children: ReactNode
  face: AccountFace
  stage: AccountView | null
}) {
  return (
    <section className="auth-section section-wrap" id="cuenta" aria-labelledby="auth-title">
      <div className="account-dossier">
        <div className="auth-heading">
          <div className="account-cover-copy">
            <span className="section-kicker">03 / Cuenta</span>
            <h2 id="auth-title" aria-label="Tu espacio privado.">
              <LivingType text="Tu espacio" />{' '}<em><LivingType text="privado." /></em>
            </h2>
          </div>
          <AccessObject face={face} />
          {stage && (
            <ol className="account-stages" role="list" aria-label="Etapas de la cuenta">
              {stages.map(({ id, label }, index) => (
                <li key={id} aria-current={id === stage ? 'step' : undefined}>
                  <span aria-hidden="true">0{index + 1}</span>{label}
                </li>
              ))}
            </ol>
          )}
        </div>
        <div className="account-controls">{children}</div>
      </div>
    </section>
  )
}
