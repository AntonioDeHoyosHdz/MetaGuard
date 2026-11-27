import { useLayoutEffect, useRef, useState, type FormEvent } from 'react'
import { createPortal } from 'react-dom'
import { ArrowRight } from 'lucide-react'
import { confirmPasswordReset, requestPasswordReset } from './authApi'

type Props = {
  target?: HTMLElement | null
  initialEmail: string
  csrfToken: string | null
  onCancel: () => void
  onCompleted: (email: string) => void
  formatError: (error: unknown) => string
}

export function PasswordReset({ target, initialEmail, csrfToken, onCancel, onCompleted, formatError }: Props) {
  const [step, setStep] = useState<'request' | 'confirm'>('request')
  const [email, setEmail] = useState(initialEmail)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const inFlight = useRef(false)
  const nonce = useRef(0)
  const input = useRef<HTMLInputElement>(null)

  useLayoutEffect(() => () => { nonce.current += 1 }, [csrfToken])
  useLayoutEffect(() => { input.current?.focus() }, [step, target])

  async function request(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!csrfToken || inFlight.current) return
    const address = email.trim()
    if (!address) return
    setError('')
    setNotice('')
    if ((event.nativeEvent as SubmitEvent).submitter?.getAttribute('value') === 'use-code') {
      setEmail(address)
      setStep('confirm')
      return
    }
    const version = nonce.current
    inFlight.current = true
    setBusy(true)
    try {
      await requestPasswordReset(address, csrfToken)
      if (version !== nonce.current) return
      setEmail(address)
      setNotice('Si el correo corresponde a una cuenta verificada, podrás recibir un código. Revisa también el correo no deseado.')
      setStep('confirm')
    } catch (cause) {
      if (version === nonce.current) setError(formatError(cause))
    } finally {
      inFlight.current = false
      if (version === nonce.current) setBusy(false)
    }
  }

  async function confirm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!csrfToken || inFlight.current) return
    const fields = new FormData(event.currentTarget)
    const code = String(fields.get('code') ?? '').trim().toLowerCase()
    const factor = String(fields.get('factor') ?? '').trim().toLowerCase()
    const password = String(fields.get('password') ?? '')
    const matches = password === fields.get('confirmation')
    for (const field of ['code', 'factor', 'password', 'confirmation']) fields.delete(field)
    event.currentTarget.reset()
    setError('')
    setNotice('')
    if (!matches) {
      setError('Las contraseñas no coinciden. Vuelve a ingresar los datos.')
      input.current?.focus()
      return
    }
    const version = nonce.current
    inFlight.current = true
    setBusy(true)
    try {
      await confirmPasswordReset(email, code, password, factor, csrfToken)
      if (version === nonce.current) onCompleted(email)
    } catch (cause) {
      if (version === nonce.current) {
        const status = typeof cause === 'object' && cause !== null && 'status' in cause ? cause.status : 0
        setError(status === 400 || status === 401
          ? 'No pudimos restablecer la contraseña. Revisa que los códigos sean válidos y elige una contraseña nueva de al menos 15 caracteres.'
          : formatError(cause))
      }
    } finally {
      inFlight.current = false
      if (version === nonce.current) setBusy(false)
    }
  }

  const form = (
    <div className="account-panel">
      {notice && <p className="auth-message auth-notice" role="status">{notice}</p>}
      {error && <p className="auth-message auth-error" role="alert">{error}</p>}
      {step === 'request' ? (
        <form key="request" className="auth-card" aria-labelledby="password-reset-title" onSubmit={request}>
          <h3 id="password-reset-title">Recuperar contraseña</h3>
          <p>Usa el correo verificado de tu cuenta. No necesitas recordar la contraseña anterior.</p>
          <label htmlFor="reset-email">Correo de tu cuenta</label>
          <input ref={input} id="reset-email" name="email" type="email" autoComplete="username" spellCheck={false} maxLength={254} required value={email} onChange={(event) => setEmail(event.target.value)} />
          <button className="auth-button" type="submit" disabled={busy || !csrfToken}>{busy ? 'Solicitando…' : 'Pedir código de recuperación'} <ArrowRight size={18} aria-hidden="true" /></button>
          <button className="auth-button auth-secondary" type="submit" value="use-code" disabled={busy || !csrfToken}>Ya tengo un código de recuperación</button>
          <button className="auth-button auth-secondary" type="button" onClick={onCancel} disabled={busy}>Volver a iniciar sesión</button>
        </form>
      ) : (
        <form key="confirm" className="auth-card" aria-labelledby="password-reset-title" onSubmit={confirm}>
          <h3 id="password-reset-title">Elige una contraseña nueva</h3>
          <p>El código del correo vence a los 15 minutos. Al restablecer la contraseña, se cerrarán las sesiones anteriores.</p>
          <label htmlFor="reset-code">Código del correo</label>
          <input ref={input} id="reset-code" name="code" autoComplete="one-time-code" spellCheck={false} required minLength={32} maxLength={34} />
          <label htmlFor="reset-factor">Código del autenticador o de respaldo</label>
          <small id="reset-factor-help">Es obligatorio solo si activaste la verificación en dos pasos.</small>
          <input id="reset-factor" name="factor" type="password" autoComplete="off" aria-describedby="reset-factor-help" maxLength={34} />
          <label htmlFor="reset-password">Nueva contraseña</label>
          <small id="reset-password-help">Usa al menos 15 caracteres.</small>
          <input id="reset-password" name="password" type="password" autoComplete="new-password" aria-describedby="reset-password-help" required minLength={15} maxLength={1024} />
          <label htmlFor="reset-confirmation">Repite la nueva contraseña</label>
          <input id="reset-confirmation" name="confirmation" type="password" autoComplete="new-password" required minLength={15} maxLength={1024} />
          <button className="auth-button" type="submit" disabled={busy || !csrfToken}>{busy ? 'Verificando…' : 'Restablecer contraseña'} <ArrowRight size={18} aria-hidden="true" /></button>
          <button className="auth-button auth-secondary" type="button" disabled={busy} onClick={() => { setNotice(''); setError(''); setStep('request') }}>Cambiar correo o solicitar otro código</button>
          <button className="auth-button auth-secondary" type="button" onClick={onCancel} disabled={busy}>Volver a iniciar sesión</button>
        </form>
      )}
    </div>
  )
  return target === undefined ? form : target ? createPortal(form, target) : null
}
