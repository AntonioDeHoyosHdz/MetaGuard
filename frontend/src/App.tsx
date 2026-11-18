import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import {
  ArrowDown, ArrowRight, ArrowUpRight, Check, ChevronDown, CircleHelp,
  FileImage, Fingerprint, Layers3, LockKeyhole, MapPin, Menu, ScanLine,
  Shield, ShieldCheck, Sparkles, X,
} from 'lucide-react'
import './App.css'
import {
  completeMfaLogin,
  getAuthStatus,
  login,
  logout,
  register,
  verifyEmail,
} from './authApi'

const Scene = lazy(() => import('./Scene'))

type Risk = 'Alto' | 'Medio' | 'Bajo'
type DemoStep = 'carga' | 'analisis' | 'resultado'
type AuthState = 'loading' | 'anonymous' | 'authenticated' | 'unavailable'

function authErrorMessage(error: unknown): string {
  const status = typeof error === 'object' && error !== null && 'status' in error
    ? Number(error.status)
    : 0
  if (status === 429) return 'Hay demasiados intentos. Esperá un momento antes de volver a probar.'
  if (status === 403) return 'No se pudo validar el origen o la protección de seguridad.'
  if (status === 401) return 'No se pudieron validar las credenciales o el código.'
  if (status === 400 || status === 409 || status === 422) return 'No se pudo completar la solicitud con esos datos.'
  return 'El servicio de autenticación no está disponible. Intentá de nuevo más tarde.'
}

const demoSteps: { id: DemoStep; number: string; label: string }[] = [
  { id: 'carga', number: '01', label: 'Carga' },
  { id: 'analisis', number: '02', label: 'Análisis' },
  { id: 'resultado', number: '03', label: 'Resultado' },
]

const example: Record<Risk, { label: string; detail: string; icon: typeof MapPin }[]> = {
  Alto: [
    { label: 'Ubicación GPS', detail: 'Puede revelar dónde se tomó una imagen.', icon: MapPin },
    { label: 'Autoría', detail: 'Puede identificar a la persona que creó el archivo.', icon: Fingerprint },
  ],
  Medio: [
    { label: 'Dispositivo', detail: 'Puede revelar el modelo utilizado.', icon: FileImage },
    { label: 'Software', detail: 'Puede mostrar la herramienta de edición.', icon: Layers3 },
  ],
  Bajo: [
    { label: 'Dimensiones', detail: 'Describen el tamaño de la imagen.', icon: ScanLine },
  ],
}

const steps = [
  { n: '01', icon: FileImage, title: 'Elige un archivo', text: 'JPG, PNG o PDF. Una forma sencilla de empezar a entender lo que compartes.' },
  { n: '02', icon: ScanLine, title: 'Conoce sus datos', text: 'Visualiza qué información puede viajar junto a tu archivo y por qué importa.' },
  { n: '03', icon: ShieldCheck, title: 'Comparte con intención', text: 'El objetivo es darte más claridad antes de compartir. La limpieza aún está en desarrollo.' },
]

function App() {
  const [apiStatus, setApiStatus] = useState<'idle' | 'checking' | 'ready' | 'database-unavailable' | 'unavailable'>('idle')
  const [risk, setRisk] = useState<Risk>('Alto')
  const [demoStep, setDemoStep] = useState<DemoStep>('carga')
  const [focusDemoStage, setFocusDemoStage] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const [authState, setAuthState] = useState<AuthState>('loading')
  const [csrfToken, setCsrfToken] = useState<string | null>(null)
  const [authBusy, setAuthBusy] = useState(false)
  const [authError, setAuthError] = useState('')
  const [authNotice, setAuthNotice] = useState('')
  const [mfaPending, setMfaPending] = useState(false)
  const [registrationEmail, setRegistrationEmail] = useState('')
  const [registrationPassword, setRegistrationPassword] = useState('')
  const [verificationToken, setVerificationToken] = useState('')
  const [loginEmail, setLoginEmail] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const demoStage = useRef<HTMLDivElement>(null)
  const menuButton = useRef<HTMLButtonElement>(null)

  const refreshAuthStatus = async () => {
    setAuthState('loading')
    setAuthError('')
    try {
      const status = await getAuthStatus()
      setCsrfToken(status.csrfToken)
      setAuthState(status.authenticated ? 'authenticated' : 'anonymous')
      if (status.authenticated && !status.csrfToken) {
        setAuthError('La sesión está activa, pero falta la protección CSRF para continuar.')
      }
    } catch (error) {
      setCsrfToken(null)
      setAuthState('unavailable')
      setAuthError(authErrorMessage(error))
    }
  }

  useEffect(() => {
    void refreshAuthStatus()
  }, [])

  const submitRegistration = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!csrfToken) return setAuthError('No hay una protección CSRF disponible. Actualizá el estado de sesión.')
    setAuthBusy(true)
    setAuthError('')
    setAuthNotice('')
    try {
      await register(registrationEmail, registrationPassword, csrfToken)
      setAuthNotice('Si el registro fue aceptado, recibirás instrucciones por correo.')
      setRegistrationPassword('')
    } catch (error) {
      setAuthError(authErrorMessage(error))
    } finally {
      setAuthBusy(false)
    }
  }

  const submitEmailVerification = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!csrfToken) return setAuthError('No hay una protección CSRF disponible. Actualizá el estado de sesión.')
    setAuthBusy(true)
    setAuthError('')
    setAuthNotice('')
    try {
      await verifyEmail(verificationToken, csrfToken)
      setVerificationToken('')
      setAuthNotice('Correo verificado. Ya podés iniciar sesión.')
    } catch (error) {
      setAuthError(authErrorMessage(error))
    } finally {
      setAuthBusy(false)
    }
  }

  const submitLogin = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!csrfToken) return setAuthError('No hay una protección CSRF disponible. Actualizá el estado de sesión.')
    setAuthBusy(true)
    setAuthError('')
    setAuthNotice('')
    try {
      const result = await login(loginEmail, loginPassword, csrfToken)
      setCsrfToken(result.csrfToken)
      if (result.mfaRequired) {
        setLoginPassword('')
        setMfaPending(true)
        setAuthNotice('Se requiere el segundo factor para continuar.')
      } else {
        setAuthState('authenticated')
        setLoginPassword('')
        setAuthNotice('Sesión iniciada.')
      }
    } catch (error) {
      setAuthError(authErrorMessage(error))
    } finally {
      setAuthBusy(false)
    }
  }

  const submitMfa = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!csrfToken) return setAuthError('No hay una protección CSRF disponible. Actualizá el estado de sesión.')
    if (!loginPassword) return setAuthError('Ingresá nuevamente la contraseña para confirmar el segundo factor.')
    const password = loginPassword
    setLoginPassword('')
    setAuthBusy(true)
    setAuthError('')
    setAuthNotice('')
    try {
      const result = await completeMfaLogin(loginEmail, password, mfaCode, csrfToken)
      setCsrfToken(result.csrfToken)
      setAuthState('authenticated')
      setMfaPending(false)
      setMfaCode('')
      setLoginPassword('')
      setAuthNotice('Sesión iniciada.')
    } catch (error) {
      setAuthError(authErrorMessage(error))
    } finally {
      setLoginPassword('')
      setAuthBusy(false)
    }
  }

  const submitLogout = async () => {
    if (!csrfToken) return setAuthError('No hay una protección CSRF disponible. Actualizá el estado de sesión.')
    setAuthBusy(true)
    setAuthError('')
    setAuthNotice('')
    try {
      await logout(csrfToken)
      setAuthState('anonymous')
      setCsrfToken(null)
      setLoginPassword('')
      setMfaPending(false)
      setAuthNotice('Sesión cerrada.')
      await refreshAuthStatus()
    } catch (error) {
      setAuthError(authErrorMessage(error))
    } finally {
      setAuthBusy(false)
    }
  }

  useEffect(() => {
    if (focusDemoStage) {
      demoStage.current?.focus()
      setFocusDemoStage(false)
    }
  }, [demoStep, focusDemoStage])

  const checkApi = async () => {
    setApiStatus('checking')
    const controller = new AbortController()
    const timeout = window.setTimeout(() => controller.abort(), 5000)
    try {
      const liveResponse = await fetch('/health/live', {
        credentials: 'omit',
        cache: 'no-store',
        signal: controller.signal,
      })
      const liveBody: unknown = liveResponse.ok ? await liveResponse.json() : null
      const apiAvailable = typeof liveBody === 'object' && liveBody !== null && 'status' in liveBody && liveBody.status === 'ok'
      if (!apiAvailable) {
        setApiStatus('unavailable')
        return
      }

      try {
        const readyResponse = await fetch('/health/ready', {
          credentials: 'omit',
          cache: 'no-store',
          signal: controller.signal,
        })
        const readyBody: unknown = readyResponse.ok ? await readyResponse.json() : null
        const databaseReady = typeof readyBody === 'object' && readyBody !== null && 'status' in readyBody && readyBody.status === 'ok'
        setApiStatus(databaseReady ? 'ready' : 'database-unavailable')
      } catch {
        setApiStatus('database-unavailable')
      }
    } catch {
      setApiStatus('unavailable')
    } finally {
      window.clearTimeout(timeout)
    }
  }

  const showDemoStep = (step: DemoStep) => {
    setDemoStep(step)
    setFocusDemoStage(true)
  }

  useEffect(() => {
    if (!menuOpen) return
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setMenuOpen(false)
        menuButton.current?.focus()
      }
    }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [menuOpen])

  return (
    <div className="app-shell">
      <header className="site-header">
        <a className="brand" href="#inicio" aria-label="MetaGuard, ir al inicio">
          <span className="brand-mark"><ShieldCheck size={19} strokeWidth={2} /></span>
          <span>meta<span className="brand-light">guard</span><span className="brand-dot">.</span></span>
        </a>
        <nav className={`main-nav ${menuOpen ? 'is-open' : ''}`} aria-label="Navegación principal">
          <a href="#inicio" onClick={() => setMenuOpen(false)}>Inicio</a>
          <a href="#como-funciona" onClick={() => setMenuOpen(false)}>Cómo funciona</a>
          <a href="#demostracion" onClick={() => setMenuOpen(false)}>Demostración</a>
          <a href="#cuenta" onClick={() => setMenuOpen(false)}>Cuenta</a>
          <a href="#privacidad" onClick={() => setMenuOpen(false)}>Privacidad</a>
        </nav>
        <a className="nav-cta" href="#demostracion">Explorar <ArrowUpRight size={16} /></a>
        <button ref={menuButton} className="menu-toggle" aria-label={menuOpen ? 'Cerrar menú' : 'Abrir menú'} aria-expanded={menuOpen} onClick={() => setMenuOpen(!menuOpen)}>
          {menuOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </header>

      <main>
        <section className="hero" id="inicio" aria-labelledby="hero-title">
          <div className="hero-inner">
          <div className="hero-grid" aria-hidden="true" />
          <div className="hero-atmosphere" aria-hidden="true"><span /><span /><span /></div>
          <div className="hero-copy">
            <div className="eyebrow"><span className="status-dot" /> TU PRIVACIDAD, MÁS CLARA <span className="eyebrow-line" /></div>
            <h1 id="hero-title">Lo que compartes<br /><em>también cuenta.</em></h1>
            <p className="hero-description">Tus archivos pueden decir más de lo que imaginas. Descubre la información que llevan consigo y comparte con mayor tranquilidad.</p>
            <div className="hero-actions">
              <a className="button button-primary" href="#demostracion">Explorar la experiencia <span><ArrowUpRight size={17} /></span></a>
              <a className="button-text" href="#como-funciona"><span className="play-symbol">↘</span> Cómo funciona</a>
            </div>
            <div className="hero-note"><LockKeyhole size={14} /> Diseño de demostración. Sin procesamiento real.</div>
          </div>
          <div className="hero-visual">
            <div className="visual-glow" />
            <div className="visual-caption"><span>UN ESPACIO PARA TU PRIVACIDAD</span><span>FIG. 01 — METAGUARD</span></div>
            <div className="scene-halo" aria-hidden="true" />
            <Suspense fallback={<div className="scene" aria-hidden="true" />}><Scene /></Suspense>
            <div className="orbit-label orbit-label-top"><span className="orbit-icon"><MapPin size={15} /></span><span><small>METADATO</small> Ubicación</span><ArrowUpRight size={13} /></div>
            <div className="orbit-label orbit-label-bottom"><span className="orbit-icon"><Fingerprint size={15} /></span><span><small>METADATO</small> Identidad</span><ArrowUpRight size={13} /></div>
            <div className="visual-bottom"><span>UNA NUEVA PERSPECTIVA</span><span>✳</span></div>
          </div>
          <a className="hero-scroll" href="#como-funciona"><span>DESPLAZA PARA DESCUBRIR</span><ArrowDown size={14} /></a>
          <span className="hero-index" aria-hidden="true">01 / 03</span>
          </div>
        </section>

        <div className="trust-strip" aria-label="Principios de diseño"><span><Shield size={15} /> PRIVACIDAD POR DISEÑO</span><span className="strip-separator">✳</span><span><ScanLine size={15} /> INFORMACIÓN MÁS CLARA</span><span className="strip-separator">✳</span><span><LockKeyhole size={15} /> TÚ TIENES EL CONTROL</span><span className="strip-end">META / GUARD</span></div>

        <section className="intro section-wrap" id="como-funciona">
          <div className="section-heading"><div><span className="section-kicker"><span>✳</span> EL CONTEXTO IMPORTA</span><h2>Pequeños datos.<br /><em>Gran diferencia.</em></h2></div><p>Una foto o un documento puede contener detalles que no se ven a simple vista. MetaGuard está pensado para hacerlos más fáciles de entender.</p></div>
          <div className="steps-grid">{steps.map(({ n, icon: Icon, title, text }) => <article className="step-card" key={n}><div className="step-top"><span className="step-icon"><Icon size={22} strokeWidth={1.5} /></span><span>{n} / 03</span></div><div><h3>{title}</h3><p>{text}</p></div><ArrowUpRight className="step-arrow" size={17} /></article>)}</div>
        </section>

        <section className="section-wrap" aria-label="Estado de la API">
        <div className="api-health">
          <button type="button" onClick={checkApi} disabled={apiStatus === 'checking'}>Comprobar API</button>
          <span role="status" aria-live="polite">
            {apiStatus === 'checking' && 'Comprobando API…'}
            {apiStatus === 'ready' && 'API y base de datos disponibles; procesamiento de archivos aún no conectado.'}
            {apiStatus === 'database-unavailable' && 'API disponible; base de datos no disponible.'}
            {apiStatus === 'unavailable' && 'No se pudo comprobar la API.'}
          </span>
        </div>
        </section>

        <section className="auth-section section-wrap" id="cuenta" aria-labelledby="auth-title">
          <div className="auth-heading">
            <div>
              <span className="section-kicker"><span>✳</span> ACCESO SEGURO</span>
              <h2 id="auth-title">Tu cuenta, bajo<br /><em>tu control.</em></h2>
            </div>
            <p>El acceso usa cookies seguras y protección CSRF. Esta interfaz no guarda credenciales ni tokens en el almacenamiento del navegador.</p>
          </div>
          <div className="auth-status" role="status" aria-live="polite">
            {authState === 'loading' && 'Consultando el estado de sesión…'}
            {authState === 'anonymous' && 'No hay una sesión iniciada.'}
            {authState === 'authenticated' && 'Sesión activa.'}
            {authState === 'unavailable' && 'No se pudo consultar el estado de sesión. El servicio de autenticación puede no estar disponible.'}
          </div>
          {authError && <p className="auth-message auth-error" role="alert">{authError}</p>}
          {authNotice && <p className="auth-message auth-notice" role="status">{authNotice}</p>}
          <p className="auth-runtime-note">El registro y el acceso dependen de servicios de backend configurados; no se afirma que la autenticación pública esté activa.</p>

          {authState === 'unavailable' && (
            <button className="auth-button auth-secondary" type="button" onClick={() => void refreshAuthStatus()} disabled={authBusy}>
              Reintentar estado de sesión
            </button>
          )}

          {authState === 'authenticated' && (
            <div className="auth-session">
              {csrfToken
                ? <button className="auth-button" type="button" onClick={() => void submitLogout()} disabled={authBusy}>{authBusy ? 'Cerrando sesión…' : 'Cerrar sesión'}</button>
                : <p role="alert">La sesión está activa, pero falta la protección CSRF para cerrar sesión con seguridad.</p>}
            </div>
          )}

          {authState === 'anonymous' && (
            <div className="auth-grid">
              <form className="auth-card" onSubmit={submitRegistration}>
                <h3>Crear cuenta</h3>
                <label htmlFor="register-email">Correo para registrarte</label>
                <input id="register-email" type="email" autoComplete="email" required maxLength={254} value={registrationEmail} onChange={(event) => setRegistrationEmail(event.target.value)} />
                <label htmlFor="register-password">Contraseña nueva</label>
                <input id="register-password" type="password" autoComplete="new-password" required minLength={15} maxLength={1024} value={registrationPassword} onChange={(event) => setRegistrationPassword(event.target.value)} />
                <button className="auth-button" type="submit" disabled={authBusy || !csrfToken}>{authBusy ? 'Enviando…' : 'Crear cuenta'}</button>
              </form>

              <form className="auth-card" onSubmit={submitEmailVerification}>
                <h3>Verificar correo</h3>
                <p>Ingresá el token recibido por correo. El token se mantiene solo en este formulario.</p>
                <label htmlFor="verify-token">Token de verificación</label>
                <input id="verify-token" type="text" autoComplete="one-time-code" required maxLength={128} value={verificationToken} onChange={(event) => setVerificationToken(event.target.value)} />
                <button className="auth-button auth-secondary" type="submit" disabled={authBusy || !csrfToken}>{authBusy ? 'Verificando…' : 'Verificar correo'}</button>
              </form>

              {!mfaPending ? (
                <form className="auth-card" onSubmit={submitLogin}>
                  <h3>Iniciar sesión</h3>
                  <label htmlFor="login-email">Correo para iniciar sesión</label>
                  <input id="login-email" type="email" autoComplete="username" required maxLength={254} value={loginEmail} onChange={(event) => setLoginEmail(event.target.value)} />
                  <label htmlFor="login-password">Contraseña de la cuenta</label>
                  <input id="login-password" type="password" autoComplete="current-password" required maxLength={1024} value={loginPassword} onChange={(event) => setLoginPassword(event.target.value)} />
                  <button className="auth-button" type="submit" disabled={authBusy || !csrfToken}>{authBusy ? 'Validando…' : 'Iniciar sesión'}</button>
                </form>
              ) : (
                <form className="auth-card" onSubmit={submitMfa}>
                  <h3>Segundo factor</h3>
                  <p>Ingresá el código de autenticación para completar el acceso.</p>
                  <label htmlFor="mfa-password">Contraseña para confirmar el segundo factor</label>
                  <input id="mfa-password" type="password" autoComplete="current-password" required maxLength={1024} value={loginPassword} onChange={(event) => setLoginPassword(event.target.value)} />
                  <label htmlFor="mfa-code">Código de autenticación</label>
                  <input id="mfa-code" type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" minLength={6} maxLength={6} required value={mfaCode} onChange={(event) => setMfaCode(event.target.value)} />
                  <button className="auth-button" type="submit" disabled={authBusy || !csrfToken || !loginPassword}>{authBusy ? 'Validando…' : 'Confirmar segundo factor'}</button>
                  <button className="auth-button auth-secondary" type="button" onClick={() => { setMfaPending(false); setMfaCode(''); setLoginPassword('') }} disabled={authBusy}>Cancelar</button>
                </form>
              )}
            </div>
          )}
        </section>

        <section className="demo-section section-wrap" id="demostracion" aria-labelledby="demo-title">
          <div className="demo-intro"><span className="section-kicker"><span>✳</span> UNA MIRADA AL INTERIOR</span><h2 id="demo-title">Entender es el<br /><em>primer paso.</em></h2><p>Un ejemplo visual de cómo podrías explorar los metadatos de un archivo. No corresponde a un archivo real.</p><div className="demo-callout"><CircleHelp size={19} /><span><strong>Vista de ejemplo</strong><br />El análisis y la limpieza aún no están conectados.</span></div><a className="button button-outline" href="#privacidad">Conoce el proyecto <ArrowRight size={16} /></a></div>
          <div className="demo-window"><div className="window-head"><div className="window-title"><span className="window-icon"><Layers3 size={16} /></span><span><strong>Explorador de metadatos</strong><small>Vista de demostración</small></span></div><span className="sample-badge"><span className="status-dot" /> EJEMPLO</span></div>
            <div className="demo-steps" role="group" aria-label="Etapas de la demostración">
              {demoSteps.map(({ id, number, label }) => <button key={id} type="button" className={`demo-step ${demoStep === id ? 'selected' : ''}`} aria-label={`${Number(number)}. ${label} de ejemplo`} aria-pressed={demoStep === id} onClick={() => showDemoStep(id)}><span>{number}</span>{label}</button>)}
            </div>
            <div className="demo-stage" aria-live="polite" tabIndex={-1} ref={demoStage}>
              {demoStep === 'carga' && <>
                <div className="sample-file"><div className="file-icon"><FileImage size={23} strokeWidth={1.5} /></div><div><strong>archivo-de-ejemplo.jpg</strong><small>Datos ficticios · JPG</small></div><span className="file-tag">SOLO VISTA</span></div>
                <div className="stage-copy"><strong>Carga de ejemplo</strong><p>Ningún archivo se ha seleccionado ni enviado. Esta vista utiliza solo un nombre ficticio.</p></div>
                <button className="demo-action" type="button" onClick={() => showDemoStep('analisis')}>Continuar al análisis de ejemplo <ArrowRight size={15} /></button>
              </>}
              {demoStep === 'analisis' && <>
                <div className="stage-illustration"><ScanLine size={24} strokeWidth={1.5} /></div>
                <div className="stage-copy"><strong>Análisis de ejemplo</strong><p>Así podría verse esta etapa. No se ha recibido un archivo ni se está ejecutando ningún análisis.</p></div>
                <button className="demo-action" type="button" onClick={() => showDemoStep('resultado')}>Ver resultado de ejemplo <ArrowRight size={15} /></button>
              </>}
              {demoStep === 'resultado' && <>
                <div className="risk-heading"><div><strong>Información de ejemplo</strong><p>Datos ficticios; no son el resultado de un análisis real.</p></div><span>03 / 03</span></div>
                <div className="risk-tabs" role="group" aria-label="Categorías de riesgo">{(['Alto', 'Medio', 'Bajo'] as Risk[]).map((item) => <button key={item} type="button" className={`risk-tab ${risk === item ? 'selected' : ''}`} aria-pressed={risk === item} onClick={() => setRisk(item)}><span className={`risk-dot ${item.toLowerCase()}`} />Riesgo {item.toLowerCase()}</button>)}</div>
                <div className="risk-list" aria-live="polite">{example[risk].map(({ label, detail, icon: Icon }) => <div className="risk-row" key={label}><span className="row-icon"><Icon size={18} /></span><span><strong>{label}</strong><small>{detail}</small></span><ArrowUpRight size={15} /></div>)}</div>
                <button className="demo-reset" type="button" onClick={() => { setRisk('Alto'); showDemoStep('carga') }}>Reiniciar ejemplo <ArrowRight size={14} /></button>
              </>}
            </div>
            <div className="window-footer"><span><Sparkles size={14} /> Información ilustrativa, no análisis real</span><span>METAGUARD / 01</span></div>
          </div>
        </section>

        <section className="privacy-section section-wrap" id="privacidad"><div className="privacy-card"><div className="privacy-symbol"><ShieldCheck size={29} strokeWidth={1.3} /></div><div><span className="section-kicker"><span>✳</span> HECHO PARA LA CLARIDAD</span><h2>Comparte con más<br /><em>confianza.</em></h2><p>Estamos construyendo una herramienta para ayudarte a entender y reducir la información que compartes. Por ahora, esta es una muestra visual del proyecto.</p><a href="#inicio" className="privacy-link">Volver al inicio <ArrowUpRight size={16} /></a></div><span className="privacy-decoration" aria-hidden="true">✳</span></div></section>
      </main>
      <footer className="footer section-wrap"><a className="brand footer-brand" href="#inicio"><span className="brand-mark"><ShieldCheck size={18} /></span><span>meta<span className="brand-light">guard</span><span className="brand-dot">.</span></span></a><p>Un poco más de privacidad, en cada archivo.</p><span>PROYECTO EN DESARROLLO <Check size={13} /></span><a href="#inicio" aria-label="Volver al inicio"><ChevronDown className="footer-up" size={18} /></a></footer>
    </div>
  )
}

export default App
