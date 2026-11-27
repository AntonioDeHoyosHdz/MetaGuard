import { useEffect, useRef, useState, type FormEvent } from 'react'
import { createPortal } from 'react-dom'
import {
  beginAuthenticatorRecovery,
  beginAuthenticatorSetup,
  confirmAuthenticatorRecovery,
  confirmAuthenticatorSetup,
  type AuthenticatorRecoverySetup,
  type AuthenticatorSetup,
} from './authApi'

export type MfaFlow = { kind: 'enroll' } | { kind: 'recover'; email: string }

type Props = {
  target?: HTMLElement | null
  flow: MfaFlow
  csrfToken: string
  isSessionCurrent: () => boolean
  onCancel: () => void
  onCompleted: (codes: string[]) => void
  onSessionInvalid: () => void
  onConfirmationUncertain: () => void
}

type RequestPhase = 'preparing' | 'confirming'
const codePattern = '[0-9a-f]{32}'
const otpPattern = '[0-9]{6}'
const expiryFormat = new Intl.DateTimeFormat('es', { dateStyle: 'short', timeStyle: 'short' })

function statusOf(error: unknown): number {
  return typeof error === 'object' && error !== null && 'status' in error
    ? Number(error.status)
    : 0
}

function requestError(status: number): string {
  if (status === 429) return 'Demasiados intentos. Espera un momento antes de volver a intentar.'
  if (status === 409) return 'La cuenta ya tiene un autenticador o hay una configuración pendiente. Si hay una configuración pendiente, espera a que caduque.'
  if (status === 401 || status === 400 || status === 422) return 'No se pudieron validar los datos. Revisa los códigos. Si la solicitud caducó, vuelve a iniciar el proceso.'
  if (status === 403) return 'No se pudo comprobar la seguridad de la sesión. Vuelve al inicio de sesión y reintenta.'
  return 'No se pudo completar la solicitud. Intenta de nuevo más tarde.'
}

export function MfaSettings({
  target, flow, csrfToken, isSessionCurrent, onCancel, onCompleted, onSessionInvalid, onConfirmationUncertain,
}: Props) {
  const [setup, setSetup] = useState<AuthenticatorSetup | AuthenticatorRecoverySetup | null>(null)
  const [busy, setBusy] = useState<RequestPhase | null>(null)
  const [error, setError] = useState('')
  const inFlight = useRef<RequestPhase | null>(null)
  const mounted = useRef(false)
  const heading = useRef<HTMLHeadingElement>(null)
  const formRef = useRef<HTMLFormElement>(null)
  const recovery = flow.kind === 'recover'

  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false }
  }, [])

  useEffect(() => { heading.current?.focus() }, [setup, target])

  useEffect(() => {
    if (!setup) return
    const remaining = setup.expiresAt * 1000 - Date.now()
    const timeout = window.setTimeout(() => {
      formRef.current?.reset()
      setSetup(null)
      setError('La clave temporal caducó. Vuelve a preparar el autenticador.')
    }, Math.max(0, Math.min(remaining, 2_147_483_647)))
    return () => window.clearTimeout(timeout)
  }, [setup])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (inFlight.current || !isSessionCurrent()) return
    const form = event.currentTarget
    const fields = new FormData(form)
    const password = String(fields.get('password') ?? '')
    const recoveryCode = String(fields.get('recovery-code') ?? '')
    const code = String(fields.get('otp') ?? '')
    form.reset()
    const needsPassword = !setup || recovery
    if (
      (needsPassword && (!password || password.length > 1024)) ||
      (recovery && !/^[0-9a-f]{32}$/.test(recoveryCode)) ||
      (setup && !/^[0-9]{6}$/.test(code))
    ) {
      setError('Completa la contraseña y los códigos que solicita este paso.')
      return
    }
    if (setup && setup.expiresAt * 1000 <= Date.now()) {
      setSetup(null)
      setError('La clave temporal caducó. Vuelve a preparar el autenticador.')
      return
    }

    const phase = setup ? 'confirming' : 'preparing'
    inFlight.current = phase
    setBusy(phase)
    setError('')
    const isCurrent = () => mounted.current && isSessionCurrent()
    try {
      if (!setup) {
        const next = flow.kind === 'recover'
          ? await beginAuthenticatorRecovery(flow.email, password, recoveryCode, csrfToken)
          : await beginAuthenticatorSetup(password, csrfToken)
        if (isCurrent()) setSetup(next)
        return
      }
      let codes: string[]
      if (flow.kind === 'recover') {
        if (!('setupToken' in setup)) return
        codes = await confirmAuthenticatorRecovery(
          flow.email, password, recoveryCode, setup.setupToken, code, csrfToken,
        )
      } else {
        codes = await confirmAuthenticatorSetup(code, csrfToken)
      }
      if (isCurrent()) {
        setSetup(null)
        onCompleted(codes)
      }
    } catch (error) {
      if (!isCurrent()) return
      const status = statusOf(error)
      if (phase === 'confirming' && (status === 0 || status >= 500 || status === 403)) {
        setSetup(null)
        onConfirmationUncertain()
      } else if (status === 403) {
        onSessionInvalid()
      } else {
        setError(requestError(status))
      }
    } finally {
      inFlight.current = null
      if (isCurrent()) setBusy(null)
    }
  }

  const form = (
    <form ref={formRef} className="auth-card mfa-card" aria-labelledby="mfa-settings-title" aria-busy={busy !== null} onSubmit={submit}>
      <h3 id="mfa-settings-title" ref={heading} tabIndex={-1}>
        {setup ? 'Verificar el autenticador nuevo' : recovery ? 'Reemplazar autenticador' : 'Configurar autenticador'}
      </h3>
      {!setup && (recovery
        ? <p>Usa tu contraseña y uno de tus códigos de recuperación. El autenticador anterior sigue activo hasta que confirmes el nuevo.</p>
        : <p>Tu aplicación de autenticación generará un código cuando inicies sesión. Para conectarla, confirma primero tu contraseña.</p>)}
      {setup && (
        <div className="mfa-key">
          <p>Abre tu aplicación de autenticación y añade una cuenta llamada MetaGuard. Elige una clave basada en tiempo y escribe esta clave. No la compartas.</p>
          <code translate="no">{setup.secret}</code>
          <p>Caduca el <time dateTime={new Date(setup.expiresAt * 1000).toISOString()}>{expiryFormat.format(setup.expiresAt * 1000)}</time>.</p>
          {recovery && <p>Vuelve a ingresar tu contraseña y el mismo código de recuperación.</p>}
        </div>
      )}
      {(!setup || recovery) && <>
        <label htmlFor="mfa-settings-password">Contraseña actual</label>
        <input id="mfa-settings-password" name="password" type="password" autoComplete="current-password" required maxLength={1024} disabled={busy !== null} />
      </>}
      {recovery && <>
        <label htmlFor="mfa-settings-recovery">Código de recuperación anterior</label>
        <input id="mfa-settings-recovery" name="recovery-code" type="password" autoComplete="off" spellCheck={false} required pattern={codePattern} minLength={32} maxLength={32} disabled={busy !== null} />
      </>}
      {setup && <>
        <label htmlFor="mfa-settings-otp">Código del nuevo autenticador</label>
        <input id="mfa-settings-otp" name="otp" type="text" inputMode="numeric" autoComplete="one-time-code" spellCheck={false} required pattern={otpPattern} minLength={6} maxLength={6} disabled={busy !== null} />
      </>}
      {error && <p className="auth-message auth-error" role="alert">{error}</p>}
      <div className="mfa-actions">
        <button className="auth-button" type="submit" disabled={busy !== null}>
          {busy !== null ? 'Verificando…' : setup
            ? recovery ? 'Confirmar reemplazo' : 'Confirmar autenticador'
            : recovery ? 'Preparar reemplazo' : 'Preparar autenticador'}
        </button>
        <button
          className="auth-button auth-secondary"
          type="button"
          onClick={onCancel}
          disabled={busy === 'confirming'}
        >
          {recovery ? 'Volver al segundo factor' : 'Cancelar configuración'}
        </button>
      </div>
    </form>
  )
  return target === undefined ? form : target ? createPortal(form, target) : null
}

export function RecoveryCodes({ codes, onAcknowledge }: { codes: string[]; onAcknowledge: () => void }) {
  const heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { heading.current?.focus() }, [])
  return (
    <section className="auth-card mfa-card" aria-labelledby="mfa-codes-title">
      <h3 id="mfa-codes-title" tabIndex={-1} ref={heading}>Guarda los códigos de recuperación</h3>
      <p>Tu autenticador está activo. Guarda estos códigos en un lugar seguro: se muestran solo ahora y cada uno se usa una sola vez.</p>
      <ul className="mfa-recovery-codes" aria-label="Códigos de recuperación nuevos">
        {codes.map(code => <li key={code}><code translate="no">{code}</code></li>)}
      </ul>
      <p>Después, inicia sesión con un código nuevo de tu aplicación de autenticación.</p>
      <button className="auth-button" type="button" onClick={onAcknowledge}>Guardé los códigos</button>
    </section>
  )
}
