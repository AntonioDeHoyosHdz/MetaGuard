import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { flushSync } from 'react-dom'
import { watchSession } from './sessionPrivacy'
import {
  ArrowRight, ArrowUpRight, ChevronDown, CircleHelp,
  Download, FileImage, Layers3, Menu,
  ScanLine, ShieldCheck, Sparkles, Trash2, X,
} from 'lucide-react'
import PrivacyHero, { LivingType } from './PrivacyHero'
import AccountDossier, { type AccountView } from './AccountDossier'
import './Studio.css'
import {
  changePassword,
  completeEmailLogin,
  completeMfaLogin,
  getAuthStatus,
  login,
  logout,
  register,
  resendVerification,
  verifyEmail,
} from './authApi'
import { MfaSettings, RecoveryCodes, type MfaFlow } from './MfaSettings'
import { PasswordReset } from './PasswordReset'
import { SecurityActivity } from './SecurityActivity'
import { isPlainAnchorClick, mainViews, resolveView, viewHref, type NavigateToView, type View } from './viewNavigation'
import {
  analyzeUpload,
  deleteReport,
  downloadFile,
  fileErrorMessage,
  getReport,
  getReports,
  issueDownloadToken,
  uploadFile,
  type ReportResource,
  type VirusTotalFileResult,
  type VirusTotalResults,
} from './fileApi'

type AuthState = 'loading' | 'anonymous' | 'authenticated' | 'unavailable'
type ReportsState = 'idle' | 'loading' | 'ready' | 'unavailable'

function authErrorMessage(error: unknown): string {
  const status = typeof error === 'object' && error !== null && 'status' in error
    ? Number(error.status)
    : 0
  if (status === 404) return 'Esta función no está disponible en el servidor conectado.'
  if (status === 429) return 'Has hecho varios intentos. Espera un momento antes de volver a intentarlo.'
  if (status === 403) return 'No pudimos verificar esta solicitud. Recarga la página y vuelve a intentarlo.'
  if (status === 401) return 'No pudimos confirmar los datos. Revisa el correo, la contraseña o el código e inténtalo de nuevo.'
  if (status === 400 || status === 409 || status === 422) return 'No se pudo completar la solicitud con esos datos.'
  return 'No pudimos conectar con tu cuenta. Vuelve a intentarlo en unos minutos.'
}

const formatNames: Record<string, string> = {
  'image/jpeg': 'JPG', 'image/png': 'PNG', 'application/pdf': 'PDF',
}
function cleanDownloadName(mediaType: string): string {
  switch (mediaType) {
    case 'image/jpeg': return 'metaguard-limpio.jpg'
    case 'image/png': return 'metaguard-limpio.png'
    case 'application/pdf': return 'metaguard-limpio.pdf'
    default: return 'metaguard-limpio.bin'
  }
}
const categoryNames: Record<string, string> = {
  author: 'Autor', color_profile: 'Perfil de color', date_time: 'Fecha y hora',
  device_model: 'Modelo del dispositivo', document_info: 'Información del documento',
  gps: 'Ubicación', image_metadata: 'Información de la imagen', manufacturer_notes: 'Notas del fabricante',
  path: 'Ruta del archivo', serial_number: 'Número de serie', software: 'Programa utilizado',
  thumbnail: 'Miniatura', xmp: 'Metadatos XMP',
}
const verdictNames: Record<string, string> = {
  malicious: 'Detecciones maliciosas', suspicious: 'Sospechosos', undetected: 'Sin detecciones',
  harmless: 'Sin riesgo identificado', timeout: 'Sin respuesta', 'confirmed-timeout': 'Tiempo agotado',
  failure: 'Errores', 'type-unsupported': 'Formato no compatible',
}
const dateFormat = new Intl.DateTimeFormat('es', { dateStyle: 'medium', timeStyle: 'short' })
function formatDate(value: string): string {
  const timestamp = Date.parse(value)
  return Number.isFinite(timestamp) ? dateFormat.format(timestamp) : 'Fecha no disponible'
}

const steps = [
  { n: '01', icon: FileImage, title: 'Elige un archivo', text: 'Selecciona una foto JPG o PNG, o un documento PDF que quieras compartir.' },
  { n: '02', icon: ScanLine, title: 'Revisa lo que contiene', text: 'Descubre si el archivo incluye detalles como el dispositivo, la fecha o el nombre del autor.' },
  { n: '03', icon: ShieldCheck, title: 'Descarga tu copia', text: 'Conserva el original y descarga una copia sin los metadatos detectados antes de compartirla.' },
]

function App() {
  const [view, setView] = useState(() => resolveView(window.location))
  const currentView = useRef(view)
  const mainContent = useRef<HTMLElement>(null)
  const [accountFlowTarget, setAccountFlowTarget] = useState<HTMLDivElement | null>(null)
  const activityOpen = view === 'activity'
  const accountVisible = view === 'account' || activityOpen
  const mainView = activityOpen ? 'account' : view
  const viewName = activityOpen ? 'Actividad de seguridad' : mainViews.find(entry => entry.id === mainView)?.name
  const [accountView, setAccountView] = useState<AccountView>('login')
  const [resendOpen, setResendOpen] = useState(false)
  const [passwordResetOpen, setPasswordResetOpen] = useState(false)
  const [passwordOpen, setPasswordOpen] = useState(false)
  const focusAccountInput = useRef(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const [authState, setAuthState] = useState<AuthState>('loading')
  const [csrfToken, setCsrfToken] = useState<string | null>(null)
  const [authBusy, setAuthBusy] = useState(false)
  const [authError, setAuthError] = useState('')
  const [authNotice, setAuthNotice] = useState('')
  const [loginChallenge, setLoginChallenge] = useState<'authenticator' | 'email' | null>(null)
  const [mfaFlow, setMfaFlow] = useState<{ flow: MfaFlow; version: number } | null>(null)
  const [mfaRecoveryCodes, setMfaRecoveryCodes] = useState<string[] | null>(null)
  const [registrationEmail, setRegistrationEmail] = useState('')
  const [registrationPassword, setRegistrationPassword] = useState('')
  const [verificationToken, setVerificationToken] = useState('')
  const [loginEmail, setLoginEmail] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [virusTotalConsent, setVirusTotalConsent] = useState(false)
  const [virusTotalResult, setVirusTotalResult] = useState<VirusTotalResults | null>(null)
  const [fileBusy, setFileBusy] = useState(false)
  const [fileStatus, setFileStatus] = useState('')
  const [fileError, setFileError] = useState('')
  const [reports, setReports] = useState<ReportResource[]>([])
  const [reportsState, setReportsState] = useState<ReportsState>('idle')
  const [reportsError, setReportsError] = useState('')
  const [reportsRevision, setReportsRevision] = useState(0)
  const [selectedReport, setSelectedReport] = useState<ReportResource | null>(null)
  const [reportActionId, setReportActionId] = useState('')
  const [deleteCandidate, setDeleteCandidate] = useState<string | null>(null)
  const workspaceVersion = useRef(0)
  const sessionEvents = useRef<ReturnType<typeof watchSession> | null>(null)
  const menuButton = useRef<HTMLButtonElement>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  const reportsHeading = useRef<HTMLHeadingElement>(null)
  const deleteButton = useRef<HTMLButtonElement | null>(null)
  const cancelDeletionButton = useRef<HTMLButtonElement>(null)
  const openEnrollmentButton = useRef<HTMLButtonElement>(null)
  const openPasswordButton = useRef<HTMLButtonElement>(null)
  const restorePasswordFocus = useRef(false)
  const openRecoveryButton = useRef<HTMLButtonElement>(null)
  const returnMfaFocus = useRef<MfaFlow['kind'] | null>(null)

  const selectView = useCallback((next: View) => {
    const previous = currentView.current
    if (next === previous) return
    currentView.current = next
    if ((previous === 'account' || previous === 'activity') && next !== 'account' && next !== 'activity') {
      setRegistrationPassword('')
      setLoginPassword('')
      setVerificationToken('')
      setMfaCode('')
      setPasswordOpen(false)
      restorePasswordFocus.current = false
    }
    if (previous === 'files') {
      setDeleteCandidate(null)
      deleteButton.current = null
    }
    setMenuOpen(false)
    setView(next)
  }, [])

  useEffect(() => {
    const syncRoute = () => selectView(resolveView(window.location))
    window.addEventListener('popstate', syncRoute)
    window.addEventListener('hashchange', syncRoute)
    return () => {
      window.removeEventListener('popstate', syncRoute)
      window.removeEventListener('hashchange', syncRoute)
    }
  }, [selectView])

  const lastView = useRef(view)
  useLayoutEffect(() => {
    document.title = view === 'home' ? 'MetaGuard — Privacidad para tus archivos' : `${viewName} — MetaGuard`
    if (lastView.current === view) return
    lastView.current = view
    if (document.scrollingElement) document.scrollingElement.scrollTop = 0
    const activityHeading = activityOpen && document.getElementById('security-activity-title')
    ;(activityHeading || mainContent.current)?.focus({ preventScroll: true })
  }, [view, viewName, activityOpen])

  useEffect(() => {
    if (accountVisible && loginChallenge === 'email') document.getElementById('email-login-password')?.focus()
  }, [accountVisible, loginChallenge])

  const navigate: NavigateToView = (event, next) => {
    if (!isPlainAnchorClick(event)) return
    event.preventDefault()
    const href = viewHref(next)
    if (`${window.location.pathname}${window.location.hash}` !== href) window.history.pushState(null, '', href)
    if (next === currentView.current) {
      setMenuOpen(false)
      mainContent.current?.focus()
    } else {
      selectView(next)
    }
  }

  const clearSelectedFile = () => {
    setSelectedFile(null)
    if (fileInput.current) fileInput.current.value = ''
  }

  const showAccountView = (view: AccountView) => {
    focusAccountInput.current = true
    setAccountView(view)
    setResendOpen(false)
    setPasswordResetOpen(false)
    setAuthError('')
    setAuthNotice('')
    setRegistrationPassword('')
    setLoginPassword('')
    setVerificationToken('')
  }

  useEffect(() => {
    if (!accountVisible || !focusAccountInput.current || authState !== 'anonymous' || passwordResetOpen) return
    focusAccountInput.current = false
    const id = { login: 'login-email', register: 'register-email', verify: resendOpen ? 'resend-email' : 'verify-token' }[accountView]
    document.getElementById(id)?.focus()
  }, [accountVisible, accountView, resendOpen, authState, passwordResetOpen])

  useEffect(() => {
    if (passwordOpen) {
      document.getElementById('password-current')?.focus()
    } else if (restorePasswordFocus.current) {
      restorePasswordFocus.current = false
      openPasswordButton.current?.focus()
    }
  }, [passwordOpen])

  const clearAuthInputs = () => {
    setAccountView('login')
    setResendOpen(false)
    setPasswordResetOpen(false)
    setRegistrationEmail('')
    setRegistrationPassword('')
    setVerificationToken('')
    setLoginEmail('')
    setLoginPassword('')
    setMfaCode('')
    setLoginChallenge(null)
  }

  // Invalidate continuations before changing session state; stale work must not
  // update the next account's view or send follow-up requests with its cookies.
  const resetPrivateWorkspace = () => {
    workspaceVersion.current += 1
    setMfaFlow(null)
    setMfaRecoveryCodes(null)
    setPasswordOpen(false)
    restorePasswordFocus.current = false
    clearSelectedFile()
    setVirusTotalConsent(false)
    setVirusTotalResult(null)
    setFileBusy(false)
    setFileStatus('')
    setFileError('')
    setReports([])
    setReportsState('idle')
    setReportsError('')
    setSelectedReport(null)
    setReportActionId('')
    setDeleteCandidate(null)
    deleteButton.current = null
  }

  const clearSession = (next: 'loading' | 'unavailable') => {
    resetPrivateWorkspace()
    clearAuthInputs()
    setAuthBusy(false)
    setAuthState(next)
    setCsrfToken(null)
    setAuthError('')
  }

  const refreshAuthStatus = async () => {
    clearSession('loading')
    const version = workspaceVersion.current
    try {
      const status = await getAuthStatus()
      if (version !== workspaceVersion.current) return
      setCsrfToken(status.csrfToken)
      setAuthState(status.authenticated ? 'authenticated' : 'anonymous')
      if (!status.csrfToken) {
        setAuthError('No pudimos preparar tu sesión. Vuelve a intentarlo para continuar.')
      }
    } catch (error) {
      if (version !== workspaceVersion.current) return
      setAuthState('unavailable')
      setAuthError(authErrorMessage(error))
    }
  }

  useEffect(() => {
    const reactToNotice = (notice: 'lock' | 'changed') => {
      setAuthNotice('')
      if (notice === 'lock') clearSession('unavailable')
      else void refreshAuthStatus()
    }
    const events = watchSession(reactToNotice)
    sessionEvents.current = events
    // Hide the DOM before the browser freezes it; reacquire status on restore.
    const hide = (event: PageTransitionEvent) => {
      if (event.persisted) flushSync(() => reactToNotice('lock'))
    }
    const show = (event: PageTransitionEvent) => {
      if (event.persisted) flushSync(() => reactToNotice('changed'))
    }
    window.addEventListener('pagehide', hide)
    window.addEventListener('pageshow', show)
    void refreshAuthStatus()
    return () => {
      workspaceVersion.current += 1
      sessionEvents.current = null
      events.close()
      window.removeEventListener('pagehide', hide)
      window.removeEventListener('pageshow', show)
    }
  }, [])

  useEffect(() => {
    if (deleteCandidate !== null) cancelDeletionButton.current?.focus()
  }, [deleteCandidate])

  useEffect(() => {
    if (mfaFlow || !returnMfaFocus.current) return
    const button = returnMfaFocus.current === 'recover' ? openRecoveryButton : openEnrollmentButton
    returnMfaFocus.current = null
    button.current?.focus()
  }, [mfaFlow])

  useEffect(() => {
    if (authState !== 'authenticated' || !csrfToken || mfaFlow) return

    let current = true
    const version = workspaceVersion.current
    setReportsState('loading')
    setReportsError('')
    void getReports(csrfToken)
      .then((items) => {
        if (!current || version !== workspaceVersion.current) return
        setReports(items)
        setReportsState('ready')
      })
      .catch((error: unknown) => {
        if (!current || version !== workspaceVersion.current) return
        setReportsError(fileErrorMessage(error))
        setReportsState('unavailable')
        if (typeof error === 'object' && error !== null && 'status' in error && [401, 403].includes(Number(error.status))) {
          // A persistent denial must not cause status -> reports -> status loops.
          clearSession('unavailable')
          setAuthError(fileErrorMessage(error))
        }
      })

    return () => { current = false }
  }, [authState, csrfToken, reportsRevision, mfaFlow])

  const submitRegistration = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!csrfToken) return setAuthError('No pudimos preparar tu sesión. Vuelve a intentarlo para continuar.')
    setAuthBusy(true)
    setAuthError('')
    setAuthNotice('')
    const version = workspaceVersion.current
    try {
      await register(registrationEmail, registrationPassword, csrfToken)
      if (version !== workspaceVersion.current) return
      showAccountView('verify')
      setAuthNotice('Si podemos registrar tu cuenta, recibirás un código por correo. Revisa también la carpeta de correo no deseado.')
      setRegistrationPassword('')
    } catch (error) {
      if (version === workspaceVersion.current) setAuthError(authErrorMessage(error))
    } finally {
      if (version === workspaceVersion.current) setAuthBusy(false)
    }
  }

  const openResend = (open: boolean) => {
    focusAccountInput.current = true
    setResendOpen(open)
    setAuthError('')
    setAuthNotice('')
  }

  const openPasswordReset = () => {
    setLoginPassword('')
    setAuthError('')
    setAuthNotice('')
    setPasswordResetOpen(true)
  }

  const completePasswordReset = (email: string) => {
    sessionEvents.current?.notify('changed')
    void refreshAuthStatus()
    focusAccountInput.current = true
    setLoginEmail(email)
    setAuthNotice('Contraseña restablecida. Inicia sesión con tu nueva contraseña.')
  }

  const submitResendVerification = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (authBusy || !csrfToken) return
    const form = event.currentTarget
    const fields = new FormData(form)
    const email = String(fields.get('email') ?? '')
    const password = String(fields.get('password') ?? '')
    const passwordInput = form.elements.namedItem('password')
    if (passwordInput instanceof HTMLInputElement) passwordInput.value = ''
    fields.delete('password')
    setAuthBusy(true)
    setAuthError('')
    setAuthNotice('')
    const version = workspaceVersion.current
    try {
      await resendVerification(email, password, csrfToken)
      if (version !== workspaceVersion.current) return
      openResend(false)
      setVerificationToken('')
      setAuthNotice('Si los datos corresponden a una cuenta pendiente, podrás recibir un nuevo código. Revisa también el correo no deseado.')
    } catch (error) {
      if (version === workspaceVersion.current) setAuthError(authErrorMessage(error))
    } finally {
      if (version === workspaceVersion.current) setAuthBusy(false)
    }
  }

  const submitEmailVerification = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!csrfToken) return setAuthError('No pudimos preparar tu sesión. Vuelve a intentarlo para continuar.')
    setAuthBusy(true)
    setAuthError('')
    setAuthNotice('')
    const version = workspaceVersion.current
    try {
      await verifyEmail(verificationToken, csrfToken)
      if (version !== workspaceVersion.current) return
      setVerificationToken('')
      showAccountView('login')
      setAuthNotice('Correo verificado. Ya puedes iniciar sesión.')
    } catch (error) {
      if (version === workspaceVersion.current) setAuthError(authErrorMessage(error))
    } finally {
      if (version === workspaceVersion.current) setAuthBusy(false)
    }
  }

  const submitLogin = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!csrfToken) return setAuthError('No pudimos preparar tu sesión. Vuelve a intentarlo para continuar.')
    setAuthBusy(true)
    setAuthError('')
    setAuthNotice('')
    const version = workspaceVersion.current
    try {
      const result = await login(loginEmail, loginPassword, csrfToken)
      if (version !== workspaceVersion.current) return
      sessionEvents.current?.notify('changed')
      setAuthBusy(false)
      setCsrfToken(result.csrfToken)
      if (result.emailChallengeRequired) {
        setLoginPassword('')
        setLoginChallenge('email')
        setAuthNotice('Para proteger tu cuenta, te pedimos un código adicional enviado a tu correo.')
      } else if (result.mfaRequired) {
        setLoginPassword('')
        setLoginChallenge('authenticator')
        setAuthNotice('Confirma tu identidad con tu aplicación de autenticación.')
      } else {
        resetPrivateWorkspace()
        clearAuthInputs()
        setAuthState('authenticated')
        setAuthNotice('Sesión iniciada.')
      }
    } catch (error) {
      if (version === workspaceVersion.current) setAuthError(authErrorMessage(error))
    } finally {
      if (version === workspaceVersion.current) setAuthBusy(false)
    }
  }

  const submitMfa = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!csrfToken) return setAuthError('No pudimos preparar tu sesión. Vuelve a intentarlo para continuar.')
    if (!loginPassword) return setAuthError('Escribe de nuevo tu contraseña para confirmar tu identidad.')
    const password = loginPassword
    const usingEmail = loginChallenge === 'email'
    const code = usingEmail ? mfaCode.trim().toLowerCase() : mfaCode
    if (usingEmail) setMfaCode('')
    setLoginPassword('')
    setAuthBusy(true)
    setAuthError('')
    setAuthNotice('')
    const version = workspaceVersion.current
    try {
      const completeProof = usingEmail ? completeEmailLogin : completeMfaLogin
      const result = await completeProof(loginEmail, password, code, csrfToken)
      if (version !== workspaceVersion.current) return
      sessionEvents.current?.notify('changed')
      setAuthBusy(false)
      resetPrivateWorkspace()
      clearAuthInputs()
      setCsrfToken(result.csrfToken)
      setAuthState('authenticated')
      setAuthNotice('Sesión iniciada.')
    } catch (error) {
      if (version === workspaceVersion.current) setAuthError(authErrorMessage(error))
    } finally {
      if (version === workspaceVersion.current) {
        setLoginPassword('')
        setAuthBusy(false)
      }
    }
  }

  const submitLogout = async () => {
    if (!csrfToken) return setAuthError('No pudimos preparar tu sesión. Vuelve a intentarlo para continuar.')
    clearSession('loading')
    const version = workspaceVersion.current
    sessionEvents.current?.notify('lock')
    setAuthBusy(true)
    setAuthError('')
    setAuthNotice('')
    try {
      await logout(csrfToken)
      if (version === workspaceVersion.current) {
        setAuthNotice('Sesión cerrada.')
        // Establish the fresh anonymous CSRF cookie before waking other tabs.
        await refreshAuthStatus()
      }
      sessionEvents.current?.notify('changed')
    } catch {
      if (version !== workspaceVersion.current) return
      setAuthState('unavailable')
      setAuthError('No se pudo confirmar el cierre de sesión. Comprueba tu sesión y vuelve a intentarlo.')
      setAuthBusy(false)
    }
  }

  const showPasswordChange = (open: boolean) => {
    restorePasswordFocus.current = !open
    setPasswordOpen(open)
    setAuthError('')
    setAuthNotice('')
  }

  const submitPasswordChange = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!csrfToken || fileActionsBlocked || !passwordOpen) return
    const form = event.currentTarget
    const fields = new FormData(form)
    const current = String(fields.get('current-password') ?? '')
    const next = String(fields.get('new-password') ?? '')
    const confirmation = String(fields.get('confirm-password') ?? '')
    form.reset()
    fields.delete('current-password')
    fields.delete('new-password')
    fields.delete('confirm-password')
    setAuthError('')
    setAuthNotice('')
    if (next !== confirmation) {
      setAuthError('Las contraseñas nuevas no coinciden. Vuelve a escribirlas.')
      document.getElementById('password-current')?.focus()
      return
    }

    setAuthBusy(true)
    const version = workspaceVersion.current
    try {
      await changePassword(current, next, csrfToken)
      sessionEvents.current?.notify('lock')
      if (version === workspaceVersion.current) {
        setAuthNotice('Contraseña cambiada. Vuelve a iniciar sesión con la nueva contraseña.')
        await refreshAuthStatus()
      }
      sessionEvents.current?.notify('changed')
    } catch (error) {
      if (version !== workspaceVersion.current) return
      const status = typeof error === 'object' && error !== null && 'status' in error ? error.status : 0
      if (status === 0 || status === 403 || status === 503) {
        sessionEvents.current?.notify('lock')
        clearSession('unavailable')
        setAuthError('No pudimos confirmar el cambio. Comprueba tu sesión antes de volver a intentarlo.')
      } else if (status === 401) {
        // A denial may mean the current password was wrong or the session was revoked.
        // Hide the previous workspace before asking which session is still active.
        const refresh = refreshAuthStatus()
        const refreshVersion = workspaceVersion.current
        await refresh
        if (refreshVersion === workspaceVersion.current) {
          setAuthError('No pudimos confirmar tu contraseña actual o tu sesión.')
        }
      } else if (status === 400) {
        setAuthError('Elige una contraseña nueva y distinta de la actual, de al menos 15 caracteres.')
      } else {
        setAuthError(authErrorMessage(error))
      }
    } finally {
      if (version === workspaceVersion.current) setAuthBusy(false)
    }
  }

  const openMfaFlow = (flow: MfaFlow) => {
    if (!csrfToken || authBusy) return
    if (flow.kind === 'enroll' && (fileBusy || reportActionId !== '' || deleteCandidate)) return
    setLoginPassword('')
    setMfaCode('')
    setAuthError('')
    setAuthNotice('')
    setMfaFlow({ flow, version: workspaceVersion.current })
  }

  const completeMfaChange = (codes: string[]) => {
    if (!mfaFlow || mfaFlow.version !== workspaceVersion.current) return
    sessionEvents.current?.notify('changed')
    resetPrivateWorkspace()
    clearAuthInputs()
    setCsrfToken(null)
    setAuthState('anonymous')
    setAuthError('')
    setAuthNotice('')
    setMfaRecoveryCodes(codes)
  }

  const recordFileFailure = (error: unknown) => {
    if (typeof error === 'object' && error !== null && 'status' in error && [401, 403].includes(Number(error.status))) {
      void refreshAuthStatus()
    }
    setFileError(fileErrorMessage(error))
    setFileStatus('')
    setVirusTotalResult(null)
  }

  const submitFile = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!csrfToken || !selectedFile || fileActionsBlocked) return
    const version = workspaceVersion.current
    setFileBusy(true)
    setFileError('')
    setVirusTotalResult(null)
    setFileStatus('Subiendo archivo…')
    try {
      const upload = await uploadFile(selectedFile, csrfToken)
      if (version !== workspaceVersion.current) return
      setFileStatus('Analizando tu archivo…')
      const report = await analyzeUpload(upload.uploadId, csrfToken, virusTotalConsent)
      if (version !== workspaceVersion.current) return
      setSelectedReport(report)
      setVirusTotalResult(report.virus_total)
      setFileStatus('Tu reporte está listo. Revisa los detalles o descarga la copia limpia.')
      setReportsRevision((revision) => revision + 1)
    } catch (error) {
      if (version === workspaceVersion.current) recordFileFailure(error)
    } finally {
      if (version === workspaceVersion.current) setFileBusy(false)
    }
  }

  const openReport = async (reportId: string) => {
    if (!csrfToken || fileActionsBlocked) return
    const version = workspaceVersion.current
    setReportActionId(reportId)
    setFileError('')
    setVirusTotalResult(null)
    setFileStatus('Consultando el reporte…')
    try {
      const report = await getReport(reportId, csrfToken)
      if (version !== workspaceVersion.current) return
      setSelectedReport(report)
      setFileStatus('Ya puedes leer los detalles del reporte.')
    } catch (error) {
      if (version === workspaceVersion.current) recordFileFailure(error)
    } finally {
      if (version === workspaceVersion.current) setReportActionId('')
    }
  }

  const downloadReport = async (reportId: string) => {
    if (!csrfToken || fileActionsBlocked) return
    const version = workspaceVersion.current
    setReportActionId(reportId)
    setFileError('')
    setFileStatus('Preparando tu descarga…')
    let objectUrl: string | null = null
    try {
      const issued = await issueDownloadToken(reportId, csrfToken)
      if (version !== workspaceVersion.current) return
      const file = await downloadFile(issued.token, csrfToken)
      if (version !== workspaceVersion.current) return
      objectUrl = URL.createObjectURL(file)
      const link = document.createElement('a')
      link.href = objectUrl
      link.download = cleanDownloadName(file.type)
      link.hidden = true
      document.body.appendChild(link)
      link.click()
      link.remove()
      setFileStatus('Descarga iniciada.')
    } catch (error) {
      if (version === workspaceVersion.current) recordFileFailure(error)
    } finally {
      if (objectUrl) window.setTimeout(() => URL.revokeObjectURL(objectUrl as string), 0)
      if (version === workspaceVersion.current) {
        setReportActionId('')
      }
    }
  }

  const cancelDeletion = () => {
    setDeleteCandidate(null)
    deleteButton.current?.focus()
    deleteButton.current = null
  }

  const removeReport = async (reportId: string) => {
    if (!csrfToken || reportId !== deleteCandidate || actionInProgress) return
    const version = workspaceVersion.current
    setDeleteCandidate(null)
    deleteButton.current = null
    reportsHeading.current?.focus()
    setReportActionId(reportId)
    setFileError('')
    setFileStatus('Eliminando reporte…')
    try {
      await deleteReport(reportId, csrfToken)
      if (version !== workspaceVersion.current) return
      setSelectedReport((current) => current?.report_id === reportId ? null : current)
      setVirusTotalResult(null)
      setFileStatus('Reporte eliminado.')
      setReportsRevision((revision) => revision + 1)
    } catch (error) {
      if (version === workspaceVersion.current) recordFileFailure(error)
    } finally {
      if (version === workspaceVersion.current) setReportActionId('')
    }
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

  const actionInProgress = authState !== 'authenticated' || authBusy || mfaFlow !== null || fileBusy || reportActionId !== ''
  const fileActionsBlocked = actionInProgress || deleteCandidate !== null

  return (
    <div className="app-shell studio-theme">
      <a className="skip-link" href="#contenido-principal" onClick={event => {
        if (!isPlainAnchorClick(event)) return
        event.preventDefault()
        setMenuOpen(false)
        mainContent.current?.focus()
      }}>Saltar al contenido principal</a>
      <header className="site-header">
        <a className="brand" href={viewHref('home')} onClick={event => navigate(event, 'home')} aria-label="MetaGuard, ir al inicio">
          <span className="brand-mark"><Layers3 size={20} strokeWidth={2.3} /></span>
          <span>Meta<span className="brand-light">Guard</span><span className="brand-dot">.</span></span>
        </a>
        <button ref={menuButton} type="button" className="menu-toggle" aria-label={menuOpen ? 'Cerrar menú' : 'Abrir menú'} aria-expanded={menuOpen} aria-controls="navegacion-principal" onClick={() => setMenuOpen(open => !open)}>
          Menú {menuOpen ? <X size={17} /> : <Menu size={17} />}
        </button>
        <nav id="navegacion-principal" className={`main-nav ${menuOpen ? 'is-open' : ''}`} aria-label="Navegación principal">
          {mainViews.map(({ id, name }) => <a key={id} href={viewHref(id)} aria-current={id === mainView ? 'page' : undefined} onClick={event => navigate(event, id)}>{name}</a>)}
        </nav>
        {authState === 'authenticated'
          ? <a className="nav-cta" href={viewHref('files')} onClick={event => navigate(event, 'files')}>Mis archivos <ArrowUpRight size={16} /></a>
          : <a className="nav-cta" href={viewHref('account')} onClick={event => navigate(event, 'account')}>Mi cuenta <ArrowUpRight size={16} /></a>}
      </header>

      <main id="contenido-principal" className="view-main" ref={mainContent} tabIndex={-1} aria-label={viewName}>
        {view === 'home' && <PrivacyHero authenticated={authState === 'authenticated'} navigate={navigate} />}

        {view === 'guide' && <section className="intro section-wrap" id="como-funciona" aria-labelledby="guide-title">
          <div className="section-heading"><div><span className="section-kicker">02 / Cómo funciona</span><h1 className="view-heading" id="guide-title" aria-label="Del original a la copia."><LivingType text="Del original a la copia." /></h1></div><p>Conserva el original y decide qué versión compartir.</p></div>
          <div className="steps-grid">{steps.map(({ n, icon: Icon, title, text }) => <article className="step-card" key={n}><div className="step-top"><span className="step-icon"><Icon size={22} strokeWidth={1.5} /></span><span>{n} / 03</span></div><div><h2>{title}</h2><p>{text}</p></div></article>)}</div>
          <a className="primary view-next" href={viewHref('files')} onClick={event => navigate(event, 'files')}>Ir a archivos y reportes <ArrowRight size={16} /></a>
        </section>}

        {accountVisible && <>
          <h1 className="view-sr-only">Cuenta</h1>
          <AccountDossier
          face={mfaFlow || loginChallenge === 'authenticator' ? 'mfa' : authState === 'authenticated' ? 'session' : passwordResetOpen || loginChallenge === 'email' ? 'verify' : accountView}
          stage={authState === 'anonymous' && !mfaFlow && !loginChallenge && !mfaRecoveryCodes && !passwordResetOpen ? accountView : null}
        >
          <div className="account-topline">
            <span className="account-wordmark"><Layers3 size={15} aria-hidden="true" /> Cuenta MetaGuard</span>
            <div className="auth-status" data-state={authState} role="status" aria-live="polite">
              {authState === 'loading' && 'Consultando el estado de sesión…'}
              {authState === 'anonymous' && 'No hay una sesión iniciada.'}
              {authState === 'authenticated' && 'Sesión activa.'}
              {authState === 'unavailable' && 'No pudimos comprobar si tu sesión está abierta.'}
            </div>
          </div>
          {authError && <p className="auth-message auth-error" role="alert">{authError}</p>}
          {authNotice && <p className="auth-message auth-notice" role="status">{authNotice}</p>}
          {activityOpen && authState === 'anonymous' && !mfaRecoveryCodes && (
            <p className="account-route-note">Inicia sesión para consultar la actividad de seguridad de tu cuenta.</p>
          )}

          {authState !== 'loading' && !csrfToken && !mfaRecoveryCodes && (
            <button className="auth-button auth-secondary" type="button" onClick={() => void refreshAuthStatus()} disabled={authBusy}>
              Volver a comprobar mi sesión
            </button>
          )}

          {authState === 'authenticated' && (
            <div className="auth-session">
              {csrfToken ? <>
                {!mfaFlow && <a className="auth-button" href={viewHref('files')} onClick={event => navigate(event, 'files')}>Ir a mis archivos <ArrowRight size={15} /></a>}
                {!mfaFlow && !activityOpen && <a className="auth-button auth-secondary" href={viewHref('activity')} onClick={event => navigate(event, 'activity')}>Ver actividad de seguridad</a>}
                {!mfaFlow && activityOpen && <a className="auth-button auth-secondary" href={viewHref('account')} onClick={event => navigate(event, 'account')}>Ocultar actividad de seguridad</a>}
                <button className="auth-button auth-secondary" type="button" onClick={() => void submitLogout()} disabled={authBusy || mfaFlow !== null}>{authBusy ? 'Cerrando sesión…' : 'Cerrar sesión'}</button>
                {!mfaFlow && !passwordOpen && (
                  <button className="auth-button auth-secondary" type="button" ref={openPasswordButton} onClick={() => showPasswordChange(true)} disabled={fileActionsBlocked}>Cambiar contraseña</button>
                )}
                {!mfaFlow && !passwordOpen && (
                  <button className="auth-button auth-secondary" type="button" ref={openEnrollmentButton} onClick={() => openMfaFlow({ kind: 'enroll' })} disabled={fileActionsBlocked}>
                    Configurar autenticador
                  </button>
                )}
              </> : <p role="alert">Vuelve a comprobar tu sesión antes de hacer cambios.</p>}
            </div>
          )}

          {authState === 'authenticated' && csrfToken && activityOpen && !mfaFlow && !passwordOpen && (
            <SecurityActivity key={csrfToken} csrfToken={csrfToken} onDenied={() => {
              clearSession('unavailable')
              setAuthError('No se pudo verificar tu sesión para consultar la actividad.')
            }} />
          )}

          {passwordOpen && authState === 'authenticated' && csrfToken && (
            <form className="auth-card mfa-card" aria-labelledby="password-change-title" aria-busy={authBusy} onSubmit={submitPasswordChange}>
              <h3 id="password-change-title">Cambiar contraseña</h3>
              <p>Al guardar, se cierran todas tus sesiones. Tu autenticador y códigos de recuperación no cambian.</p>
              <label htmlFor="password-current">Contraseña actual de la cuenta</label>
              <input id="password-current" name="current-password" type="password" autoComplete="current-password" required maxLength={1024} disabled={authBusy} />
              <label htmlFor="password-new">Nueva contraseña de la cuenta</label>
              <input id="password-new" name="new-password" type="password" autoComplete="new-password" aria-describedby="password-help" required minLength={15} maxLength={1024} disabled={authBusy} />
              <small id="password-help">Usa al menos 15 caracteres.</small>
              <label htmlFor="password-confirm">Confirma la nueva contraseña</label>
              <input id="password-confirm" name="confirm-password" type="password" autoComplete="new-password" required minLength={15} maxLength={1024} disabled={authBusy} />
              <div className="mfa-actions">
                <button className="auth-button" type="submit" disabled={authBusy || fileActionsBlocked}>{authBusy ? 'Guardando…' : 'Guardar nueva contraseña'}</button>
                <button className="auth-button auth-secondary" type="button" disabled={authBusy} onClick={() => showPasswordChange(false)}>Cancelar</button>
              </div>
            </form>
          )}

          {(mfaFlow || passwordResetOpen) && <div ref={setAccountFlowTarget} />}

          {mfaRecoveryCodes && <RecoveryCodes codes={mfaRecoveryCodes} onAcknowledge={() => void refreshAuthStatus()} />}

          {authState === 'anonymous' && !mfaFlow && !mfaRecoveryCodes && !passwordResetOpen && (
            <div className="account-panel">
              {!loginChallenge && accountView === 'login' && (
                <form className="auth-card" aria-labelledby="account-form-title" onSubmit={submitLogin}>
                  <h3 id="account-form-title">Iniciar sesión</h3>
                  <p>Entra para analizar tus archivos, descargar copias limpias y volver a tus reportes.</p>
                  <label htmlFor="login-email">Correo para iniciar sesión</label>
                  <input id="login-email" name="email" type="email" autoComplete="username" spellCheck={false} required maxLength={254} value={loginEmail} onChange={(event) => setLoginEmail(event.target.value)} />
                  <label htmlFor="login-password">Contraseña de la cuenta</label>
                  <input id="login-password" name="password" type="password" autoComplete="current-password" required maxLength={1024} value={loginPassword} onChange={(event) => setLoginPassword(event.target.value)} />
                  <button className="auth-button" type="submit" disabled={authBusy || !csrfToken}>{authBusy ? 'Validando…' : 'Iniciar sesión'} <ArrowRight size={18} aria-hidden="true" /></button>
                  <button className="auth-button auth-secondary" type="button" disabled={authBusy || !csrfToken} onClick={openPasswordReset}>Olvidé mi contraseña</button>
                </form>
              )}
              {loginChallenge === 'authenticator' && (
                <form className="auth-card" aria-labelledby="account-form-title" onSubmit={submitMfa}>
                  <h3 id="account-form-title">Segundo factor</h3>
                  <p>Escribe de nuevo tu contraseña y el código de seis dígitos de tu aplicación.</p>
                  <label htmlFor="mfa-password">Contraseña para confirmar el segundo factor</label>
                  <input id="mfa-password" name="password" type="password" autoComplete="current-password" required maxLength={1024} value={loginPassword} onChange={(event) => setLoginPassword(event.target.value)} />
                  <label htmlFor="mfa-code">Código de autenticación</label>
                  <input id="mfa-code" name="mfa-code" type="text" inputMode="numeric" autoComplete="one-time-code" spellCheck={false} pattern="[0-9]{6}" minLength={6} maxLength={6} required value={mfaCode} onChange={(event) => setMfaCode(event.target.value)} />
                  <button className="auth-button" type="submit" disabled={authBusy || !csrfToken || !loginPassword}>{authBusy ? 'Validando…' : 'Confirmar segundo factor'} <ArrowRight size={18} aria-hidden="true" /></button>
                  <button className="auth-button auth-secondary" type="button" ref={openRecoveryButton} onClick={() => openMfaFlow({ kind: 'recover', email: loginEmail })} disabled={authBusy || !csrfToken}>No tengo acceso al autenticador</button>
                  <button className="auth-button auth-secondary" type="button" onClick={() => { setLoginChallenge(null); setMfaCode(''); setLoginPassword('') }} disabled={authBusy}>Cancelar</button>
                </form>
              )}
              {loginChallenge === 'email' && (
                <form className="auth-card" aria-labelledby="account-form-title" onSubmit={submitMfa}>
                  <h3 id="account-form-title">Confirma el inicio de sesión</h3>
                  <p>Escribe de nuevo tu contraseña y el código de inicio enviado a tu correo. El código vence a los 5 minutos.</p>
                  <label htmlFor="email-login-password">Contraseña para confirmar el inicio</label>
                  <input id="email-login-password" name="password" type="password" autoComplete="current-password" required maxLength={1024} value={loginPassword} onChange={event => setLoginPassword(event.target.value)} />
                  <label htmlFor="email-login-code">Código de inicio enviado por correo</label>
                  <input id="email-login-code" name="email-code" type="text" autoComplete="one-time-code" spellCheck={false} minLength={32} maxLength={34} required value={mfaCode} onChange={event => setMfaCode(event.target.value)} />
                  <button className="auth-button" type="submit" disabled={authBusy || !csrfToken || !loginPassword}>{authBusy ? 'Validando…' : 'Confirmar inicio de sesión'} <ArrowRight size={18} aria-hidden="true" /></button>
                  <button className="auth-button auth-secondary" type="button" onClick={() => { setLoginChallenge(null); setMfaCode(''); showAccountView('login') }} disabled={authBusy}>Cancelar</button>
                </form>
              )}
              {!loginChallenge && accountView === 'register' && (
                <form className="auth-card" aria-labelledby="account-form-title" onSubmit={submitRegistration}>
                  <h3 id="account-form-title">Crear cuenta</h3>
                  <p>Usa tu correo y elige una contraseña para tu cuenta.</p>
                  <label htmlFor="register-email">Correo para registrarte</label>
                  <input id="register-email" name="email" type="email" autoComplete="email" spellCheck={false} required maxLength={254} value={registrationEmail} onChange={(event) => setRegistrationEmail(event.target.value)} />
                  <label htmlFor="register-password">Contraseña nueva</label>
                  <small id="register-password-help">Usa al menos 15 caracteres.</small>
                  <input id="register-password" aria-describedby="register-password-help" name="password" type="password" autoComplete="new-password" required minLength={15} maxLength={1024} value={registrationPassword} onChange={(event) => setRegistrationPassword(event.target.value)} />
                  <button className="auth-button" type="submit" disabled={authBusy || !csrfToken}>{authBusy ? 'Enviando…' : 'Crear cuenta'} <ArrowRight size={18} aria-hidden="true" /></button>
                </form>
              )}
              {!loginChallenge && accountView === 'verify' && !resendOpen && (
                <form className="auth-card" aria-labelledby="account-form-title" onSubmit={submitEmailVerification}>
                  <h3 id="account-form-title">Verificar correo</h3>
                  <p>Si recibiste un código por correo, escríbelo aquí y selecciona «Verificar correo».</p>
                  <label htmlFor="verify-token">Código de verificación</label>
                  <input id="verify-token" name="verification-token" type="text" autoComplete="one-time-code" spellCheck={false} required maxLength={128} value={verificationToken} onChange={(event) => setVerificationToken(event.target.value)} />
                  <button className="auth-button" type="submit" disabled={authBusy || !csrfToken}>{authBusy ? 'Verificando…' : 'Verificar correo'} <ArrowRight size={18} aria-hidden="true" /></button>
                  <button className="auth-button auth-secondary" type="button" disabled={authBusy || !csrfToken} onClick={() => openResend(true)}>Solicitar otro código</button>
                </form>
              )}
              {!loginChallenge && accountView === 'verify' && resendOpen && (
                <form className="auth-card" aria-labelledby="account-form-title" onSubmit={submitResendVerification}>
                  <h3 id="account-form-title">Solicitar otro código</h3>
                  <p>Si no recibiste el código o ya venció, usa los datos con los que te registraste.</p>
                  <label htmlFor="resend-email">Correo de tu cuenta</label>
                  <input id="resend-email" name="email" type="email" autoComplete="username" spellCheck={false} required maxLength={254} defaultValue={registrationEmail} />
                  <label htmlFor="resend-password">Contraseña que elegiste al registrarte</label>
                  <input id="resend-password" name="password" type="password" autoComplete="current-password" required maxLength={1024} />
                  <button className="auth-button" type="submit" disabled={authBusy || !csrfToken}>{authBusy ? 'Solicitando…' : 'Solicitar código'} <ArrowRight size={18} aria-hidden="true" /></button>
                  <button className="auth-button auth-secondary" type="button" disabled={authBusy} onClick={() => openResend(false)}>Volver a ingresar código</button>
                </form>
              )}
              {!loginChallenge && <div className="account-switch" role="group" aria-label="Opciones de cuenta">
                {accountView !== 'login' && <button type="button" disabled={authBusy} onClick={() => showAccountView('login')}>Ya tengo una cuenta <ArrowUpRight size={15} aria-hidden="true" /></button>}
                {accountView !== 'register' && <button type="button" disabled={authBusy} onClick={() => showAccountView('register')}>Crear una cuenta <ArrowUpRight size={15} aria-hidden="true" /></button>}
                {accountView !== 'verify' && <button type="button" disabled={authBusy} onClick={() => showAccountView('verify')}>Tengo un código de verificación <ArrowUpRight size={15} aria-hidden="true" /></button>}
              </div>}
            </div>
          )}
          </AccountDossier>
        </>}

        {view === 'files' && <section className="demo-section section-wrap" id="demostracion" aria-labelledby="demo-title">
          <div className="demo-intro">
            <span className="section-kicker"><span>✳</span> ARCHIVOS Y REPORTES</span>
            <h1 className="view-heading" id="demo-title">Tus archivos <br /><em>y reportes.</em></h1>
            <p>Sube una foto o un documento para revisar sus metadatos y obtener una copia limpia.</p>
            <div className="demo-callout" role="note"><CircleHelp size={19} /><span><strong>Tu original se conserva</strong><br />MetaGuard crea una copia. El archivo de tu dispositivo no cambia.</span></div>
            <div className="demo-callout" role="note"><ShieldCheck size={19} /><span><strong>Consulta opcional a VirusTotal</strong><br />Si lo autorizas, se consultan las huellas digitales del original y de la copia. VirusTotal nunca recibe tus archivos.</span></div>
          </div>

          <div className="demo-window">
            <div className="window-head">
              <div className="window-title"><span className="window-icon"><Layers3 size={16} /></span><span><strong>Mi espacio de archivos</strong><small>Fotos y documentos</small></span></div>
              <span className="sample-badge">JPG · PNG · PDF</span>
            </div>

            {fileError && <p className="auth-message auth-error" role="alert">{fileError}</p>}
            {authState === 'loading' && <p className="stage-copy" role="status">Abriendo tu espacio de archivos…</p>}
            {authState === 'anonymous' && <div className="stage-copy"><strong>Accede a tus archivos</strong><p>Inicia sesión para subir archivos y consultar tus reportes.</p><a className="auth-button auth-secondary" href={viewHref('account')} onClick={event => navigate(event, 'account')}>Ir a mi cuenta <ArrowRight size={15} /></a></div>}
            {(authState === 'unavailable' || (authState === 'authenticated' && !csrfToken)) && (
              <div className="stage-copy">
                <p role="alert">No pudimos abrir tus archivos. Vuelve a comprobar tu sesión para continuar.</p>
                <a className="auth-button auth-secondary" href={viewHref('account')} onClick={event => navigate(event, 'account')}>Ir a mi cuenta <ArrowRight size={15} /></a>
              </div>
            )}

            {authState === 'authenticated' && csrfToken && <>
              <form className="file-upload-form" onSubmit={submitFile} aria-busy={fileBusy}>
                <label htmlFor="analysis-file">Archivo para analizar (JPG, PNG o PDF)</label>
                <input ref={fileInput} id="analysis-file" name="file" type="file" accept="image/jpeg,image/png,application/pdf,.jpg,.jpeg,.png,.pdf" onChange={(event) => { setSelectedFile(event.target.files?.[0] ?? null); setVirusTotalConsent(false); setVirusTotalResult(null); setFileError(''); setFileStatus('') }} disabled={fileActionsBlocked} />
                {selectedFile && <p className="selected-file"><FileImage size={17} /> Archivo seleccionado: {selectedFile.name}</p>}
                <div className="auth-check-row">
                  <input
                    id="virus-total-consent"
                    type="checkbox"
                    checked={virusTotalConsent}
                    onChange={(event) => setVirusTotalConsent(event.target.checked)}
                    disabled={fileActionsBlocked}
                  />
                  <label htmlFor="virus-total-consent">Consultar en VirusTotal las huellas digitales (SHA-256) del original y de la copia limpia. No se envían los archivos, pero VirusTotal puede saber que se consultaron.</label>
                </div>
                <button className="demo-action" type="submit" disabled={fileActionsBlocked || !selectedFile}>
                  {fileBusy ? 'Procesando solicitud…' : 'Subir y analizar'} <ArrowRight size={15} />
                </button>
              </form>

              <p className="file-status" role="status">{fileStatus}</p>
              {virusTotalResult && <section className="report-detail" aria-label="Resultado de VirusTotal">
                <h4>Resultado de VirusTotal</h4>
                {(['original', 'cleaned'] as const).map((kind) => (
                  <VirusTotalFileVerdict key={kind} kind={kind} result={virusTotalResult[kind]} />
                ))}
              </section>}

              <section className="report-list" aria-labelledby="reports-title" aria-busy={reportsState === 'loading'}>
                <div className="report-list-head"><h2 id="reports-title" ref={reportsHeading} tabIndex={-1}>Tus reportes</h2><button className="report-refresh" type="button" onClick={() => setReportsRevision((revision) => revision + 1)} disabled={reportsState === 'loading' || fileActionsBlocked}>{reportsState === 'unavailable' ? 'Reintentar' : 'Actualizar'}</button></div>
                {reportsState === 'loading' && <p role="status">Consultando tus reportes…</p>}
                {reportsState === 'unavailable' && reportsError && <p className="auth-message auth-error" role="alert">{reportsError}</p>}
                {reportsState === 'ready' && reports.length === 0 && <p role="status">Aún no hay reportes.</p>}
                {reports.length > 0 && <ul className="report-items">
                  {reports.map((item) => <li className="report-row" key={item.report_id}>
                    <div className="report-summary"><strong>Reporte de archivo {formatNames[item.report.media_type]}</strong><small>Creado: <time dateTime={item.created_at}>{formatDate(item.created_at)}</time></small><small>Disponible hasta <time dateTime={item.expires_at}>{formatDate(item.expires_at)}</time></small></div>
                    <div className="report-actions">
                      <button className="auth-button auth-secondary" type="button" onClick={() => void openReport(item.report_id)} disabled={fileActionsBlocked}>Ver detalle</button>
                      <button className="auth-button auth-secondary" type="button" onClick={() => void downloadReport(item.report_id)} disabled={fileActionsBlocked}><Download size={14} /> Descargar copia limpia</button>
                      <button className="auth-button auth-secondary report-delete" type="button" onClick={(event) => {
                        deleteButton.current = event.currentTarget
                        setDeleteCandidate(item.report_id)
                      }} disabled={actionInProgress || (deleteCandidate !== null && deleteCandidate !== item.report_id)} aria-expanded={deleteCandidate === item.report_id}><Trash2 size={14} /> Eliminar reporte</button>
                    </div>
                    {deleteCandidate === item.report_id && <section className="report-confirmation" aria-label="Confirmar eliminación del reporte" onKeyDown={(event) => {
                      if (event.key === 'Escape') cancelDeletion()
                    }}>
                      <p>Se eliminará este reporte y ya no podrás descargar su copia limpia.</p>
                      <div className="report-actions">
                        <button ref={cancelDeletionButton} type="button" className="auth-button auth-secondary" onClick={cancelDeletion}>Cancelar</button>
                        <button type="button" className="auth-button" onClick={() => void removeReport(item.report_id)} disabled={actionInProgress}>Confirmar eliminación</button>
                      </div>
                    </section>}
                  </li>)}
                </ul>}
                {selectedReport && <article className="report-detail" aria-labelledby="report-detail-title">
                  <h3 id="report-detail-title">Detalles del reporte</h3>
                  <p>Tipo de archivo: {formatNames[selectedReport.report.media_type]}</p>
                  <p>Metadatos detectados: {selectedReport.report.metadata_categories.length > 0
                    ? selectedReport.report.metadata_categories.map((category) => categoryNames[category] ?? category).join(', ')
                    : 'ninguno'}</p>
                  {selectedReport.report.width !== null && selectedReport.report.height !== null && <p>Dimensiones: {selectedReport.report.width} × {selectedReport.report.height}</p>}
                  {selectedReport.report.page_count !== null && <p>Páginas: {selectedReport.report.page_count}</p>}
                  <p>{selectedReport.report.output_verified ? 'Se verificó la copia después de limpiar sus metadatos.' : 'No se ha confirmado la verificación de la copia.'}</p>
                  <p>Este reporte describe los metadatos; no determina si el archivo contiene malware.</p>
                </article>}
              </section>
            </>}

            <div className="window-footer"><span><Sparkles size={14} /> Cada enlace de descarga es de un solo uso.</span><span>METAGUARD</span></div>
          </div>
        </section>}

        {view === 'privacy' && <section className="privacy-section section-wrap" id="privacidad" aria-labelledby="privacy-title">
          <div className="privacy-card">
            <div className="privacy-symbol"><ShieldCheck size={29} strokeWidth={1.3} /></div>
            <div>
              <span className="section-kicker">Privacidad</span>
              <h1 className="view-heading" id="privacy-title" aria-label="Comparte con más confianza."><LivingType text="Comparte con más" /><br /><em><LivingType text="confianza." /></em></h1>
              <p>Tú decides si consultas VirusTotal. Con tu permiso, solo compartimos las huellas digitales del original y de su copia, nunca los archivos.</p>
              <a href={viewHref('home')} onClick={event => navigate(event, 'home')} className="privacy-link">Volver al inicio <ArrowUpRight size={16} /></a>
            </div>
          </div>
        </section>}
      </main>
      {/* The workflows outlive a view change; their forms only render into the active account. */}
      {mfaFlow && csrfToken && (
        <MfaSettings
          target={accountVisible ? accountFlowTarget : null}
          flow={mfaFlow.flow}
          csrfToken={csrfToken}
          isSessionCurrent={() => mfaFlow.version === workspaceVersion.current}
          onCancel={() => {
            returnMfaFocus.current = mfaFlow.flow.kind
            setMfaFlow(null)
          }}
          onCompleted={completeMfaChange}
          onSessionInvalid={() => void refreshAuthStatus()}
          onConfirmationUncertain={() => {
            sessionEvents.current?.notify('changed')
            setAuthNotice('No se pudo confirmar el estado del cambio. Si se completó, usa el nuevo autenticador para iniciar sesión.')
            void refreshAuthStatus()
          }}
        />
      )}
      {authState === 'anonymous' && !loginChallenge && passwordResetOpen && (
        <PasswordReset key={csrfToken ?? 'not-ready'} target={accountVisible ? accountFlowTarget : null}
          initialEmail={loginEmail} csrfToken={csrfToken}
          onCancel={() => showAccountView('login')} onCompleted={completePasswordReset}
          formatError={authErrorMessage} />
      )}
      <footer className="footer section-wrap"><a className="brand footer-brand" href={viewHref('home')} onClick={event => navigate(event, 'home')}><span className="brand-mark"><ShieldCheck size={18} /></span><span>Meta<span className="brand-light">Guard</span><span className="brand-dot">.</span></span></a><p>Un poco más de privacidad, en cada archivo.</p><span>PRIVACIDAD DE ARCHIVOS</span><a href={viewHref('home')} onClick={event => navigate(event, 'home')} aria-label="Volver al inicio"><ChevronDown className="footer-up" size={18} /></a></footer>
    </div>
  )
}

function VirusTotalFileVerdict({ kind, result }: { kind: 'original' | 'cleaned'; result: VirusTotalFileResult }) {
  const label = kind === 'original' ? 'del original' : 'de la copia limpia'
  const status = {
    found: 'Reporte encontrado',
    not_found: 'No se encontró un reporte',
    not_requested: 'VirusTotal no fue consultado.',
    rate_limited: 'Se alcanzó el límite de consultas de VirusTotal.',
    key_unavailable: 'No pudimos consultar VirusTotal. Aún puedes revisar los metadatos del archivo.',
    unavailable: 'VirusTotal no estuvo disponible; el análisis del archivo continuó.',
  }[result.status]
  return <div>
    <h5>Reporte VirusTotal {label}</h5>
    <p>{status}</p>
    {result.last_analysis_stats && <p>{Object.entries(result.last_analysis_stats)
      .map(([name, count]) => `${verdictNames[name] ?? name}: ${count}`).join(' · ')}</p>}
    {result.last_analysis_date !== null && <p>Último análisis: {new Date(result.last_analysis_date * 1000).toLocaleString('es')}</p>}
    {result.status === 'found' && <p>Un resultado sin detecciones no garantiza que el archivo sea seguro.</p>}
    {result.report_url && <a href={result.report_url} target="_blank" rel="noreferrer">Abrir reporte de VirusTotal</a>}
  </div>
}

export default App
