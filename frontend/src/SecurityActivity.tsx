import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { getSecurityEvents, type SecurityEvent, type SecurityEventKind } from './authApi'

const labels: Record<SecurityEventKind, string> = {
  login_failed: 'Intento de inicio de sesión fallido',
  mfa_failed: 'Intento de verificación en dos pasos fallido',
  upload_type_mismatch: 'Un archivo no coincidió con el formato indicado',
  rate_limit_exceeded: 'Se alcanzó un límite de seguridad',
  new_ip_login: 'Inicio de sesión desde una dirección nueva',
  dangerous_content_detected: 'Se detectó contenido activo en un documento',
  leaked_password_rejected: 'Se rechazó una contraseña presente en una filtración',
}

const formatDate = new Intl.DateTimeFormat('es', { dateStyle: 'medium', timeStyle: 'short' })

export function SecurityActivity({ csrfToken, onDenied }: { csrfToken: string; onDenied: () => void }) {
  const [items, setItems] = useState<SecurityEvent[] | null>(null)
  const [error, setError] = useState<'unavailable' | 'retry' | null>(null)
  const [revision, setRevision] = useState(0)
  const heading = useRef<HTMLHeadingElement>(null)
  const denied = useRef(onDenied)
  useLayoutEffect(() => { denied.current = onDenied })
  useLayoutEffect(() => { heading.current?.focus() }, [])

  useEffect(() => {
    let current = true
    setError(null)
    setItems(null)
    void getSecurityEvents(csrfToken)
      .then(events => { if (current) setItems(events) })
      .catch((reason: unknown) => {
        if (!current) return
        const status = typeof reason === 'object' && reason !== null && 'status' in reason ? reason.status : 0
        if (status === 401 || status === 403) denied.current()
        else setError(status === 404 ? 'unavailable' : 'retry')
      })
    return () => { current = false }
  }, [csrfToken, revision])

  return (
    <section id="actividad" className="auth-card security-activity" aria-labelledby="security-activity-title">
      <h3 id="security-activity-title" ref={heading} tabIndex={-1}>Actividad de seguridad</h3>
      <p>Consulta hasta 50 eventos de seguridad de tu cuenta de los últimos 30 días.</p>
      <p>Un intento fallido no significa que alguien haya entrado a tu cuenta.</p>
      {error ? <>
        <p role="alert">{error === 'unavailable' ? 'Esta función no está disponible en el servidor conectado.' : 'No pudimos consultar tu actividad. Vuelve a intentarlo.'}</p>
        <button className="auth-button auth-secondary" type="button" onClick={() => setRevision(value => value + 1)}>Volver a consultar actividad</button>
      </> : !items ? <p role="status">Consultando la actividad de seguridad…</p>
        : items.length === 0 ? <p role="status">No hay eventos recientes.</p>
          : <ol className="security-activity-list">
            {items.map(({ kind, created_at }, index) => <li key={`${created_at}:${kind}:${index}`}>
              <strong>{labels[kind]}</strong>
              <time dateTime={created_at}>{formatDate.format(new Date(created_at))}</time>
            </li>)}
          </ol>}
    </section>
  )
}
