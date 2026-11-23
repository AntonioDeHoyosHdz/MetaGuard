import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import App from './App'

beforeEach(() => {
  vi.resetAllMocks()
  authApiMocks.getAuthStatus.mockResolvedValue({ authenticated: false, csrfToken: 'csrf-test' })
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  window.history.replaceState(null, '', '/')
})

const fileReport = {
  report_id: 'report-123',
  report: {
    media_type: 'image/png',
    metadata_categories: ['software'],
    output_verified: true,
    width: 12,
    height: 8,
    page_count: null,
    active_content_removed: false,
    uri_links_removed: 0,
  },
  created_at: '2026-11-18T10:00:00Z',
  expires_at: '2026-11-19T10:00:00Z',
  virus_total: {
    original: { status: 'not_requested', last_analysis_stats: null, last_analysis_date: null, report_url: null },
    cleaned: { status: 'not_requested', last_analysis_stats: null, last_analysis_date: null, report_url: null },
  },
}

const apiResponse = (body: unknown, status = 200, mediaType = 'image/png') => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body,
  blob: async () => new Blob(['cleaned bytes'], { type: mediaType }),
}) as Response

function renderView(view = '/#cuenta') {
  window.history.replaceState(null, '', view)
  return render(<App />)
}

function navigateTo(name: string) {
  fireEvent.click(within(screen.getByRole('navigation', { name: 'Navegación principal' })).getByRole('link', { name }))
}

describe('MetaGuard file and report workflow', () => {
  it('lets visitors compare the example without uploading a file', async () => {
    const request = vi.fn()
    vi.stubGlobal('fetch', request)
    renderView('/')
    expect(screen.getByRole('heading', { name: /Comparte el archivo, no su historia/i })).toBeTruthy()
    const figure = within(screen.getByRole('figure', { name: 'Explora las capas de un archivo' }))
    const original = figure.getByRole('button', { name: 'Original' })
    const cleaned = figure.getByRole('button', { name: 'Copia limpia' })
    expect(figure.getByText('Ubicación incluida')).toBeTruthy()
    expect(original.getAttribute('aria-pressed')).toBe('true')
    fireEvent.click(cleaned)
    expect(cleaned.getAttribute('aria-pressed')).toBe('true')
    expect(original.getAttribute('aria-pressed')).toBe('false')
    expect(figure.getByText('Sin ubicación')).toBeTruthy()
    fireEvent.click(original)
    expect(original.getAttribute('aria-pressed')).toBe('true')
    expect(figure.getByText('Ubicación incluida')).toBeTruthy()
    navigateTo('Cuenta')
    await screen.findByText('No hay una sesión iniciada.')
    expect(request).not.toHaveBeenCalled()
  })

  it('rotates the file example with controls and arrow keys without changing the selected copy', async () => {
    renderView('/')
    const figure = screen.getByRole('figure', { name: 'Explora las capas de un archivo' })
    const viewer = within(figure)
    const scene = viewer.getByRole('group', { name: 'Orientación del archivo' })
    const camera = figure.querySelector<HTMLElement>('.layer-object')!
    fireEvent.click(viewer.getByRole('button', { name: 'Copia limpia' }))
    fireEvent.click(viewer.getByRole('button', { name: 'Girar a la derecha' }))
    expect(camera.style.getPropertyValue('--turn-y')).toBe('18deg')
    fireEvent.keyDown(scene, { key: 'ArrowUp' })
    expect(camera.style.getPropertyValue('--turn-x')).toBe('18deg')
    fireEvent.click(viewer.getByRole('button', { name: 'Centrar vista' }))
    expect(camera.style.getPropertyValue('--turn-y')).toBe('0deg')
    expect(camera.style.getPropertyValue('--turn-x')).toBe('0deg')
    expect(viewer.getByRole('button', { name: 'Copia limpia' }).getAttribute('aria-pressed')).toBe('true')
    navigateTo('Cuenta')
    await screen.findByText('No hay una sesión iniciada.')
  })

  it('guides visitors to sign in and shows registration only when requested', async () => {
    renderView('/')
    const analysis = screen.getByRole('link', { name: 'Analizar un archivo' })
    expect(analysis.getAttribute('href')).toBe('/#cuenta')
    fireEvent.click(analysis)
    await screen.findByText('No hay una sesión iniciada.')
    expect(screen.queryByRole('button', { name: 'Comprobar API' })).toBeNull()
    expect(screen.getByLabelText('Correo para iniciar sesión')).toBeTruthy()
    expect(screen.queryByLabelText('Correo para registrarte')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Crear una cuenta' }))
    expect(screen.getByLabelText('Correo para registrarte')).toBeTruthy()
    expect(document.querySelector('.access-cube')?.getAttribute('data-face')).toBe('register')
    expect(screen.queryByLabelText('Correo para iniciar sesión')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Ya tengo una cuenta' }))
    expect(screen.getByLabelText('Correo para iniciar sesión')).toBeTruthy()
  })

  it('marks the current account stage without treating a view change as verification', async () => {
    renderView()
    await screen.findByText('No hay una sesión iniciada.')

    const currentStage = () => within(screen.getByRole('list', { name: 'Etapas de la cuenta' }))
      .getAllByRole('listitem').filter((stage) => stage.getAttribute('aria-current') === 'step')
    expect(currentStage()).toHaveLength(1)
    expect(currentStage()[0]?.textContent).toContain('Acceso')

    const options = () => within(screen.getByRole('group', { name: 'Opciones de cuenta' }))
    fireEvent.click(options().getByRole('button', { name: 'Crear una cuenta' }))
    expect(document.activeElement).toBe(screen.getByLabelText('Correo para registrarte'))
    expect(currentStage()).toHaveLength(1)
    expect(currentStage()[0]?.textContent).toContain('Registro')

    fireEvent.click(options().getByRole('button', { name: 'Tengo un código de verificación' }))
    expect(document.activeElement).toBe(screen.getByLabelText('Código de verificación'))
    expect(currentStage()).toHaveLength(1)
    expect(currentStage()[0]?.textContent).toContain('Verificación')
    expect(screen.queryByText('Correo verificado. Ya puedes iniciar sesión.')).toBeNull()
    expect(authApiMocks.verifyEmail).not.toHaveBeenCalled()

    fireEvent.click(options().getByRole('button', { name: 'Ya tengo una cuenta' }))
    expect(document.activeElement).toBe(screen.getByLabelText('Correo para iniciar sesión'))
    expect(currentStage()).toHaveLength(1)
    expect(currentStage()[0]?.textContent).toContain('Acceso')
  })

  it('lets pending signups request a replacement code without claiming it was delivered', async () => {
    authApiMocks.resendVerification.mockResolvedValueOnce(undefined)
    renderView()
    await screen.findByText('No hay una sesión iniciada.')
    fireEvent.click(screen.getByRole('button', { name: 'Tengo un código de verificación' }))
    fireEvent.click(screen.getByRole('button', { name: 'Solicitar otro código' }))
    const email = screen.getByLabelText('Correo de tu cuenta')
    expect(document.activeElement).toBe(email)
    fireEvent.change(email, { target: { value: 'persona@example.test' } })
    fireEvent.change(screen.getByLabelText('Contraseña que elegiste al registrarte'), {
      target: { value: 'synthetic password only' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Solicitar código' }))
    expect(await screen.findByText(/Si los datos corresponden a una cuenta pendiente/)).toBeTruthy()
    expect(authApiMocks.resendVerification).toHaveBeenCalledExactlyOnceWith(
      'persona@example.test', 'synthetic password only', 'csrf-test',
    )
    expect(screen.queryByLabelText('Contraseña que elegiste al registrarte')).toBeNull()
    expect(document.activeElement).toBe(screen.getByLabelText('Código de verificación'))
  })

  it('opens owner-only security activity in the account without navigating away', async () => {
    authApiMocks.getAuthStatus.mockResolvedValue({ authenticated: true, csrfToken: 'activity-csrf' })
    authApiMocks.getSecurityEvents.mockResolvedValueOnce([{ kind: 'login_failed', created_at: '2026-11-21T12:00:00Z' }])
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(apiResponse({ reports: [] })))
    renderView()
    expect(authApiMocks.getSecurityEvents).not.toHaveBeenCalled()
    fireEvent.click(await screen.findByRole('link', { name: 'Ver actividad de seguridad' }))
    expect(window.location.pathname).toBe('/security/events')
    expect(await screen.findByText('Intento de inicio de sesión fallido')).toBeTruthy()
    expect(authApiMocks.getSecurityEvents).toHaveBeenCalledExactlyOnceWith('activity-csrf')
  })

  it('keeps the workspace signed out until a required sign-in email proof is accepted', async () => {
    authApiMocks.login.mockResolvedValueOnce({ authenticated: false, mfaRequired: false, emailChallengeRequired: true, csrfToken: 'mail-csrf' })
    authApiMocks.completeEmailLogin.mockResolvedValueOnce({ authenticated: true, mfaRequired: false, csrfToken: 'session-csrf' })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(apiResponse({ reports: [] })))
    renderView()
    await screen.findByText('No hay una sesión iniciada.')
    fireEvent.change(screen.getByLabelText('Correo para iniciar sesión'), { target: { value: 'synthetic@example.test' } })
    const password = { target: { value: 'synthetic sign-in password' } }
    fireEvent.change(screen.getByLabelText('Contraseña de la cuenta'), password)
    fireEvent.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
    expect(await screen.findByRole('heading', { name: 'Confirma el inicio de sesión' })).toBeTruthy()
    expect(screen.queryByRole('link', { name: 'Ver actividad de seguridad' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'No tengo acceso al autenticador' })).toBeNull()
    const code = 'a'.repeat(32)
    fireEvent.change(screen.getByLabelText('Contraseña para confirmar el inicio'), password)
    fireEvent.change(screen.getByLabelText('Código de inicio enviado por correo'), { target: { value: code } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar inicio de sesión' }))
    expect(await screen.findByText('Sesión activa.')).toBeTruthy()
    expect(authApiMocks.completeEmailLogin).toHaveBeenCalledExactlyOnceWith('synthetic@example.test', password.target.value, code, 'mail-csrf')
    expect(authApiMocks.completeMfaLogin).not.toHaveBeenCalled()
  })

  it('does not disclose a late activity response after the workspace is locked', async () => {
    authApiMocks.getAuthStatus.mockResolvedValue({ authenticated: true, csrfToken: 'activity-csrf' })
    let resolveEvents: (events: unknown) => void = () => undefined
    authApiMocks.getSecurityEvents.mockReturnValueOnce(new Promise(resolve => { resolveEvents = resolve }))
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(apiResponse({ reports: [] })))
    renderView('/security/events')
    await screen.findByText('Consultando la actividad de seguridad…')
    act(() => window.dispatchEvent(new StorageEvent('storage', { key: 'metaguard.session-invalidation', newValue: 'lock' })))
    await act(async () => { resolveEvents([{ kind: 'login_failed', created_at: '2026-11-21T12:00:00Z' }]) })
    expect(screen.queryByText('Intento de inicio de sesión fallido')).toBeNull()
    expect(screen.queryByRole('heading', { name: 'Actividad de seguridad' })).toBeNull()
  })

  it('requests a password reset generically and confirms without starting a session', async () => {
    authApiMocks.requestPasswordReset.mockResolvedValueOnce(undefined)
    authApiMocks.confirmPasswordReset.mockResolvedValueOnce(undefined)
    renderView()
    await screen.findByText('No hay una sesión iniciada.')

    fireEvent.click(screen.getByRole('button', { name: 'Olvidé mi contraseña' }))
    const email = screen.getByLabelText('Correo de tu cuenta')
    expect(document.activeElement).toBe(email)
    fireEvent.change(email, { target: { value: 'persona@example.test' } })
    fireEvent.click(screen.getByRole('button', { name: 'Pedir código de recuperación' }))
    expect(await screen.findByText(/Si el correo corresponde a una cuenta verificada/)).toBeTruthy()
    expect(authApiMocks.requestPasswordReset).toHaveBeenCalledExactlyOnceWith('persona@example.test', 'csrf-test')

    const code = screen.getByLabelText('Código del correo')
    expect(document.activeElement).toBe(code)
    const resetCode = 'abcdef0123456789'.repeat(2)
    fireEvent.change(code, { target: { value: resetCode } })
    fireEvent.change(screen.getByLabelText('Código del autenticador o de respaldo'), {
      target: { value: '123456' },
    })
    fireEvent.change(screen.getByLabelText('Nueva contraseña'), { target: { value: 'synthetic next password' } })
    fireEvent.change(screen.getByLabelText('Repite la nueva contraseña'), { target: { value: 'synthetic next password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Restablecer contraseña' }))
    expect(await screen.findByText(/Contraseña restablecida/)).toBeTruthy()
    expect(authApiMocks.confirmPasswordReset).toHaveBeenCalledExactlyOnceWith(
      'persona@example.test', resetCode, 'synthetic next password', '123456', 'csrf-test',
    )
    expect(authApiMocks.login).not.toHaveBeenCalled()
    expect(screen.queryByLabelText('Código del correo')).toBeNull()
    expect(screen.getByLabelText('Contraseña de la cuenta')).toBeTruthy()
  })

  it('accepts an already issued reset code without sending another email and clears rejected credentials', async () => {
    authApiMocks.confirmPasswordReset.mockRejectedValueOnce({ status: 401 })
    renderView()
    await screen.findByText('No hay una sesión iniciada.')
    fireEvent.click(screen.getByRole('button', { name: 'Olvidé mi contraseña' }))
    fireEvent.change(screen.getByLabelText('Correo de tu cuenta'), { target: { value: 'persona@example.test' } })
    fireEvent.click(screen.getByRole('button', { name: 'Ya tengo un código de recuperación' }))
    expect(authApiMocks.requestPasswordReset).not.toHaveBeenCalled()
    const code = screen.getByLabelText<HTMLInputElement>('Código del correo')
    const password = screen.getByLabelText<HTMLInputElement>('Nueva contraseña')
    fireEvent.change(code, { target: { value: 'a'.repeat(32) } })
    fireEvent.change(password, { target: { value: 'synthetic next password' } })
    fireEvent.change(screen.getByLabelText('Repite la nueva contraseña'), { target: { value: password.value } })
    fireEvent.click(screen.getByRole('button', { name: 'Restablecer contraseña' }))
    expect((await screen.findByRole('alert')).textContent).toMatch(/No pudimos restablecer la contraseña/)
    expect(code.value).toBe('')
    expect(password.value).toBe('')
    expect(authApiMocks.login).not.toHaveBeenCalled()
  })

  it.each([200, 401])('rechecks the signed-in workspace after password response %i', async (status) => {
    authApiMocks.getAuthStatus
      .mockResolvedValueOnce({ authenticated: true, csrfToken: 'session-csrf' })
      .mockResolvedValueOnce({ authenticated: false, csrfToken: 'preauth-csrf' })
    if (status === 401) authApiMocks.changePassword.mockRejectedValueOnce({ status })
    else authApiMocks.changePassword.mockResolvedValueOnce(undefined)
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(apiResponse({ reports: [fileReport] })))
    renderView('/#demostracion')
    await screen.findByText('Reporte de archivo PNG')
    navigateTo('Cuenta')
    fireEvent.click(screen.getByRole('button', { name: 'Cambiar contraseña' }))
    const current = screen.getByLabelText('Contraseña actual de la cuenta')
    expect(document.activeElement).toBe(current)
    fireEvent.change(current, { target: { value: 'synthetic current password' } })
    fireEvent.change(screen.getByLabelText('Nueva contraseña de la cuenta'), {
      target: { value: 'synthetic newer password' },
    })
    fireEvent.change(screen.getByLabelText('Confirma la nueva contraseña'), {
      target: { value: 'synthetic newer password' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Guardar nueva contraseña' }))
    await screen.findByLabelText('Correo para iniciar sesión')
    if (status === 200) expect(await screen.findByText(/Contraseña cambiada/)).toBeTruthy()
    else expect(await screen.findByRole('alert')).toBeTruthy()
    expect(authApiMocks.changePassword).toHaveBeenCalledExactlyOnceWith(
      'synthetic current password', 'synthetic newer password', 'session-csrf',
    )
    expect(screen.queryByLabelText('Contraseña actual de la cuenta')).toBeNull()
    navigateTo('Archivos y reportes')
    expect(screen.queryByText('Reporte de archivo PNG')).toBeNull()
  })

  it('requires an authenticated session before showing file upload controls', async () => {
    const { container } = renderView('/#demostracion')
    expect(await screen.findByText('Inicia sesión para subir archivos y consultar tus reportes.')).toBeTruthy()
    expect(container.querySelector('input[type="file"]')).toBeNull()
    fireEvent.click(screen.getByRole('link', { name: 'Ir a mi cuenta' }))
    expect(await screen.findByText('No hay una sesión iniciada.')).toBeTruthy()
  })

  it('opens and closes the navigation menu', () => {
    renderView('/')
    const button = screen.getByRole('button', { name: 'Abrir menú' })
    fireEvent.click(button)
    expect(screen.getByRole('button', { name: 'Cerrar menú' }).getAttribute('aria-expanded')).toBe('true')
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(screen.getByRole('button', { name: 'Abrir menú' }).getAttribute('aria-expanded')).toBe('false')
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Abrir menú' }))
  })

  it('uploads a real file, displays the returned report, and does not claim VirusTotal scanned it', async () => {
    authApiMocks.getAuthStatus.mockResolvedValueOnce({ authenticated: true, csrfToken: 'csrf-files' })
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(apiResponse({ reports: [] }))
      .mockResolvedValueOnce(apiResponse({ upload_id: 'upload-123', media_type: 'image/png' }, 201))
      .mockResolvedValueOnce(apiResponse(fileReport))
      .mockResolvedValueOnce(apiResponse({ reports: [fileReport] }))
    vi.stubGlobal('fetch', fetchMock)

    renderView('/')
    await waitFor(() => expect(screen.getByRole('link', { name: 'Analizar un archivo' }).getAttribute('href')).toBe('/#demostracion'))
    fireEvent.click(screen.getByRole('link', { name: 'Analizar un archivo' }))
    expect(await screen.findByText('Aún no hay reportes.')).toBeTruthy()
    fireEvent.change(screen.getByLabelText(/Archivo para analizar/), {
      target: { files: [new File([new Uint8Array([0, 1, 255])], 'photo.png', { type: 'image/png' })] },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Subir y analizar' }))

    expect(await screen.findByText('Tu reporte está listo. Revisa los detalles o descarga la copia limpia.')).toBeTruthy()
    expect(await screen.findByText('Reporte de archivo PNG')).toBeTruthy()
    expect(screen.getAllByText('VirusTotal no fue consultado.')).toHaveLength(2)
    expect((screen.getByRole('checkbox', { name: /SHA-256/ }) as HTMLInputElement).checked).toBe(false)
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/v1/uploads', expect.objectContaining({
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'image/png', 'X-CSRF-Token': 'csrf-files' },
    }))
    expect(fetchMock).toHaveBeenNthCalledWith(3, '/v1/analyses/upload-123', expect.objectContaining({
      method: 'POST', credentials: 'include',
      body: JSON.stringify({ virus_total_consent: false }),
    }))
  })

  it('sends VirusTotal consent only after opt-in and displays the minimized result', async () => {
    authApiMocks.getAuthStatus.mockResolvedValueOnce({ authenticated: true, csrfToken: 'csrf-files' })
    const analysis = {
      ...fileReport,
      virus_total: {
        original: {
          status: 'found',
          last_analysis_stats: { malicious: 1, undetected: 4 },
          last_analysis_date: 1_800_000_000,
          report_url: `https://www.virustotal.com/gui/file/${'a'.repeat(64)}`,
        },
        cleaned: {
          status: 'not_found',
          last_analysis_stats: null,
          last_analysis_date: null,
          report_url: null,
        },
      },
    }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(apiResponse({ reports: [] }))
      .mockResolvedValueOnce(apiResponse({ upload_id: 'upload-123', media_type: 'image/png' }, 201))
      .mockResolvedValueOnce(apiResponse(analysis))
      .mockResolvedValueOnce(apiResponse({ reports: [fileReport] }))
    vi.stubGlobal('fetch', fetchMock)

    renderView('/#demostracion')
    expect(await screen.findByText('Aún no hay reportes.')).toBeTruthy()
    fireEvent.change(screen.getByLabelText(/Archivo para analizar/), {
      target: { files: [new File(['synthetic'], 'file.png', { type: 'image/png' })] },
    })
    const consent = screen.getByRole('checkbox', { name: /SHA-256/ }) as HTMLInputElement
    expect(consent.checked).toBe(false)
    fireEvent.click(consent)
    fireEvent.click(screen.getByRole('button', { name: 'Subir y analizar' }))

    expect(await screen.findByText('Reporte VirusTotal del original')).toBeTruthy()
    expect(screen.getByText(/Detecciones maliciosas: 1/)).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Abrir reporte de VirusTotal' }).getAttribute('href'))
      .toBe(`https://www.virustotal.com/gui/file/${'a'.repeat(64)}`)
    expect(fetchMock).toHaveBeenNthCalledWith(3, '/v1/analyses/upload-123', expect.objectContaining({
      body: JSON.stringify({ virus_total_consent: true }),
    }))
  })

  it('clears selected file state and the input when one account logs out before another signs in', async () => {
    authApiMocks.getAuthStatus
      .mockResolvedValueOnce({ authenticated: true, csrfToken: 'csrf-account-a' })
      .mockResolvedValueOnce({ authenticated: false, csrfToken: 'csrf-before-account-b' })
    authApiMocks.logout.mockResolvedValueOnce(undefined)
    authApiMocks.login.mockResolvedValueOnce({ authenticated: true, mfaRequired: false, csrfToken: 'csrf-account-b' })
    const fetchMock = vi.fn().mockResolvedValue(apiResponse({ reports: [] }))
    vi.stubGlobal('fetch', fetchMock)

    renderView()
    expect(await screen.findByText('Sesión activa.')).toBeTruthy()
    navigateTo('Archivos y reportes')
    expect(await screen.findByText('Aún no hay reportes.')).toBeTruthy()
    fireEvent.change(screen.getByLabelText(/Archivo para analizar/), {
      target: { files: [new File(['account-a bytes'], 'account-a.png', { type: 'image/png' })] },
    })
    expect(screen.getByText('Archivo seleccionado: account-a.png')).toBeTruthy()

    navigateTo('Cuenta')
    fireEvent.click(screen.getByRole('button', { name: 'Cerrar sesión' }))
    expect(await screen.findByText('No hay una sesión iniciada.')).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Correo para iniciar sesión'), { target: { value: 'account-b@example.test' } })
    fireEvent.change(screen.getByLabelText('Contraseña de la cuenta'), { target: { value: 'account-b-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Iniciar sesión' }))

    expect(await screen.findByText('Sesión activa.')).toBeTruthy()
    navigateTo('Archivos y reportes')
    expect(screen.queryByText('Archivo seleccionado: account-a.png')).toBeNull()
    expect((screen.getByLabelText(/Archivo para analizar/) as HTMLInputElement).value).toBe('')
    expect(screen.getByRole('button', { name: 'Subir y analizar' }).hasAttribute('disabled')).toBe(true)
    expect(fetchMock.mock.calls.some(([path]) => path === '/v1/uploads')).toBe(false)
  })

  it('clears selected file state after a 401 before a different account signs in', async () => {
    authApiMocks.getAuthStatus.mockResolvedValueOnce({ authenticated: true, csrfToken: 'csrf-account-a' })
    authApiMocks.login.mockResolvedValueOnce({ authenticated: true, mfaRequired: false, csrfToken: 'csrf-account-b' })
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(apiResponse({ reports: [] }))
      .mockResolvedValueOnce(apiResponse({ detail: 'private server trace' }, 401))
      .mockResolvedValueOnce(apiResponse({ reports: [] }))
    vi.stubGlobal('fetch', fetchMock)

    renderView('/#demostracion')
    expect(await screen.findByText('Aún no hay reportes.')).toBeTruthy()
    fireEvent.change(screen.getByLabelText(/Archivo para analizar/), {
      target: { files: [new File(['account-a bytes'], 'account-a.png', { type: 'image/png' })] },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Subir y analizar' }))
    expect(await screen.findByRole('alert')).toBeTruthy()
    navigateTo('Cuenta')
    expect(await screen.findByText('No hay una sesión iniciada.')).toBeTruthy()

    fireEvent.change(screen.getByLabelText('Correo para iniciar sesión'), { target: { value: 'account-b@example.test' } })
    fireEvent.change(screen.getByLabelText('Contraseña de la cuenta'), { target: { value: 'account-b-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Iniciar sesión' }))

    expect(await screen.findByText('Sesión activa.')).toBeTruthy()
    navigateTo('Archivos y reportes')
    expect(screen.queryByText('Archivo seleccionado: account-a.png')).toBeNull()
    expect((screen.getByLabelText(/Archivo para analizar/) as HTMLInputElement).value).toBe('')
    expect(screen.getByRole('button', { name: 'Subir y analizar' }).hasAttribute('disabled')).toBe(true)
    expect(fetchMock.mock.calls.filter(([path]) => path === '/v1/uploads')).toHaveLength(1)
  })

  it.each([
    ['image/png', 'png'], ['image/jpeg', 'jpg'], ['application/pdf', 'pdf'], ['application/octet-stream', 'bin'],
  ])('downloads a private %s copy with a safe name and deletes its report', async (mediaType, extension) => {
    authApiMocks.getAuthStatus.mockResolvedValueOnce({ authenticated: true, csrfToken: 'csrf-files' })
    let reportListCalls = 0
    const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      if (input === '/v1/reports' && method === 'GET') {
        reportListCalls += 1
        return apiResponse({ reports: reportListCalls === 1 ? [fileReport] : [] })
      }
      if (input === '/v1/reports/report-123' && method === 'GET') return apiResponse(fileReport)
      if (input === '/v1/reports/report-123/download-token') return apiResponse({ token: 'opaque-one-use', expires_at: '2026-11-18T10:10:00Z' })
      if (input === '/v1/downloads' && method === 'POST' &&
        init?.body === JSON.stringify({ token: 'opaque-one-use' })) return apiResponse(null, 200, mediaType)
      if (input === '/v1/reports/report-123' && method === 'DELETE') return apiResponse(null, 204)
      throw new Error(`Unexpected request: ${method} ${input}`)
    })
    const createObjectURL = vi.fn(() => 'blob:clean-report')
    const revokeObjectURL = vi.fn()
    const clickedNames: string[] = []
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      clickedNames.push(this.download)
    })
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('URL', Object.assign(class TestURL extends URL {}, { createObjectURL, revokeObjectURL }))
    const localStorageWrite = vi.spyOn(localStorage, 'setItem')
    const sessionStorageWrite = vi.spyOn(sessionStorage, 'setItem')

    renderView('/#demostracion')
    expect(await screen.findByText('Reporte de archivo PNG')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Ver detalle' }))
    expect(await screen.findByText('Detalles del reporte')).toBeTruthy()
    expect(screen.getByText(/Metadatos detectados: Programa utilizado/)).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: 'Descargar copia limpia' }))
    expect(await screen.findByText('Descarga iniciada.')).toBeTruthy()
    expect(clickedNames).toEqual([`metaguard-limpio.${extension}`])
    await waitFor(() => expect(revokeObjectURL).toHaveBeenCalledWith('blob:clean-report'))
    expect(document.body.textContent).not.toContain('opaque-one-use')
    expect(localStorageWrite).not.toHaveBeenCalled()
    expect(sessionStorageWrite).not.toHaveBeenCalled()

    const deleteButton = screen.getByRole('button', { name: 'Eliminar reporte' })
    fireEvent.click(deleteButton)
    const confirmation = screen.getByRole('region', { name: 'Confirmar eliminación del reporte' })
    const cancel = within(confirmation).getByRole('button', { name: 'Cancelar' })
    expect(document.activeElement).toBe(cancel)
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(false)
    fireEvent.keyDown(cancel, { key: 'Escape' })
    expect(screen.queryByRole('region', { name: 'Confirmar eliminación del reporte' })).toBeNull()
    expect(document.activeElement).toBe(deleteButton)
    fireEvent.click(deleteButton)
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar eliminación' }))
    expect(await screen.findByText('Aún no hay reportes.')).toBeTruthy()
    expect(fetchMock).toHaveBeenCalledWith('/v1/reports/report-123', expect.objectContaining({ method: 'DELETE' }))
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Tus reportes' }))
  })

  it.each([
    [401, 'La sesión ha caducado. Inicia sesión de nuevo.'],
    [403, 'No pudimos verificar tu sesión. Recarga la página y vuelve a intentarlo.'],
    [404, 'El reporte o su copia ya no están disponibles.'],
    [413, 'El archivo es demasiado grande. Elige uno más pequeño.'],
    [415, 'Ese formato no es compatible. Elige un archivo JPG, PNG o PDF.'],
    [429, 'Has hecho varias solicitudes. Espera un momento antes de volver a intentarlo.'],
    [503, 'El servicio de archivos no está disponible en este momento. Vuelve a intentarlo más tarde.'],
  ])('shows a safe, accessible message for upload failure %i', async (status, message) => {
    authApiMocks.getAuthStatus.mockResolvedValueOnce({ authenticated: true, csrfToken: 'csrf-files' })
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(apiResponse({ reports: [] }))
      .mockResolvedValueOnce(apiResponse({ detail: 'private server trace' }, status))
    vi.stubGlobal('fetch', fetchMock)

    renderView('/#demostracion')
    expect(await screen.findByText('Aún no hay reportes.')).toBeTruthy()
    fireEvent.change(screen.getByLabelText(/Archivo para analizar/), {
      target: { files: [new File(['image'], 'photo.png', { type: 'image/png' })] },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Subir y analizar' }))

    expect((await screen.findByRole('alert')).textContent).toBe(message)
    expect(document.body.textContent).not.toContain('private server trace')
  })
})

const authApiMocks = vi.hoisted(() => ({
  beginAuthenticatorSetup: vi.fn(),
  confirmAuthenticatorSetup: vi.fn(),
  beginAuthenticatorRecovery: vi.fn(),
  confirmAuthenticatorRecovery: vi.fn(),
  getAuthStatus: vi.fn(),
  getSecurityEvents: vi.fn(),
  register: vi.fn(),
  verifyEmail: vi.fn(),
  resendVerification: vi.fn(),
  requestPasswordReset: vi.fn(),
  confirmPasswordReset: vi.fn(),
  changePassword: vi.fn(),
  login: vi.fn(),
  completeMfaLogin: vi.fn(),
  completeEmailLogin: vi.fn(),
  logout: vi.fn(),
}))

vi.mock('./authApi', () => authApiMocks)

const syntheticAuthenticator = { secret: 'A'.repeat(32), expiresAt: 4_102_444_800 }
const syntheticRecoveryCodes = Array.from({ length: 8 }, (_, index) => index.toString(16).padStart(32, '0'))

it('sets up an authenticator, shows the new backup codes once, and requires a new sign-in', async () => {
  authApiMocks.getAuthStatus
    .mockResolvedValueOnce({ authenticated: true, csrfToken: 'enrollment-session' })
    .mockResolvedValueOnce({ authenticated: false, csrfToken: 'new-sign-in' })
  authApiMocks.beginAuthenticatorSetup.mockResolvedValueOnce(syntheticAuthenticator)
  authApiMocks.confirmAuthenticatorSetup.mockResolvedValueOnce(syntheticRecoveryCodes)
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(apiResponse({ reports: [] })))

  renderView()
  fireEvent.click(await screen.findByRole('button', { name: 'Configurar autenticador' }))
  fireEvent.change(screen.getByLabelText('Contraseña actual'), { target: { value: 'synthetic-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Preparar autenticador' }))
  expect(await screen.findByText(syntheticAuthenticator.secret)).toBeTruthy()
  expect(screen.queryByLabelText('Contraseña actual')).toBeNull()
  expect(authApiMocks.beginAuthenticatorSetup).toHaveBeenCalledExactlyOnceWith('synthetic-password', 'enrollment-session')

  fireEvent.change(screen.getByLabelText('Código del nuevo autenticador'), { target: { value: '123456' } })
  fireEvent.click(screen.getByRole('button', { name: 'Confirmar autenticador' }))
  expect(await screen.findByText(syntheticRecoveryCodes[0])).toBeTruthy()
  expect(screen.queryByText(syntheticAuthenticator.secret)).toBeNull()
  expect(screen.queryByRole('button', { name: 'Cerrar sesión' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Iniciar sesión' })).toBeNull()
  expect(screen.queryByLabelText(/Archivo para analizar/)).toBeNull()
  expect(authApiMocks.confirmAuthenticatorSetup).toHaveBeenCalledExactlyOnceWith('123456', 'enrollment-session')

  fireEvent.click(screen.getByRole('button', { name: 'Guardé los códigos' }))
  expect(await screen.findByRole('button', { name: 'Iniciar sesión' })).toBeTruthy()
  expect(screen.queryByText(syntheticRecoveryCodes[0])).toBeNull()
  expect(authApiMocks.getAuthStatus).toHaveBeenCalledTimes(2)
})

it('replaces a lost authenticator only from the MFA challenge and requires re-entry of both credentials', async () => {
  authApiMocks.login.mockResolvedValueOnce({ authenticated: false, mfaRequired: true, csrfToken: 'recovery-challenge' })
  authApiMocks.beginAuthenticatorRecovery.mockResolvedValueOnce({ ...syntheticAuthenticator, setupToken: 'local-setup-proof' })
  authApiMocks.confirmAuthenticatorRecovery.mockResolvedValueOnce(syntheticRecoveryCodes)
  const oldRecoveryCode = 'f'.repeat(32)
  renderView()
  expect(await screen.findByRole('button', { name: 'Iniciar sesión' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'No tengo acceso al autenticador' })).toBeNull()
  fireEvent.change(screen.getByLabelText('Correo para iniciar sesión'), { target: { value: 'guest@example.test' } })
  fireEvent.change(screen.getByLabelText('Contraseña de la cuenta'), { target: { value: 'first-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
  fireEvent.click(await screen.findByRole('button', { name: 'No tengo acceso al autenticador' }))

  expect((screen.getByLabelText('Contraseña actual') as HTMLInputElement).value).toBe('')
  fireEvent.change(screen.getByLabelText('Contraseña actual'), { target: { value: 're-entered-password' } })
  fireEvent.change(screen.getByLabelText('Código de recuperación anterior'), { target: { value: oldRecoveryCode } })
  fireEvent.click(screen.getByRole('button', { name: 'Preparar reemplazo' }))
  expect(await screen.findByText(syntheticAuthenticator.secret)).toBeTruthy()
  expect((screen.getByLabelText('Contraseña actual') as HTMLInputElement).value).toBe('')
  expect((screen.getByLabelText('Código de recuperación anterior') as HTMLInputElement).value).toBe('')
  expect(authApiMocks.beginAuthenticatorRecovery).toHaveBeenCalledExactlyOnceWith(
    'guest@example.test', 're-entered-password', oldRecoveryCode, 'recovery-challenge',
  )

  const confirm = screen.getByRole('button', { name: 'Confirmar reemplazo' })
  fireEvent.submit(confirm.closest('form')!)
  expect(authApiMocks.confirmAuthenticatorRecovery).not.toHaveBeenCalled()
  fireEvent.change(screen.getByLabelText('Contraseña actual'), { target: { value: 'fresh-confirm-password' } })
  fireEvent.change(screen.getByLabelText('Código de recuperación anterior'), { target: { value: oldRecoveryCode } })
  fireEvent.change(screen.getByLabelText('Código del nuevo autenticador'), { target: { value: '123456' } })
  fireEvent.click(confirm)
  expect(await screen.findByText(syntheticRecoveryCodes[0])).toBeTruthy()
  expect(screen.queryByText('local-setup-proof')).toBeNull()
  expect(screen.queryByText(oldRecoveryCode)).toBeNull()
  expect(authApiMocks.confirmAuthenticatorRecovery).toHaveBeenCalledExactlyOnceWith(
    'guest@example.test', 'fresh-confirm-password', oldRecoveryCode, 'local-setup-proof', '123456', 'recovery-challenge',
  )
})

it('ignores an authenticator seed that comes back after the setup was canceled', async () => {
  authApiMocks.getAuthStatus.mockResolvedValueOnce({ authenticated: true, csrfToken: 'enrollment-session' })
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(apiResponse({ reports: [] })))
  let resolveSetup!: (value: typeof syntheticAuthenticator) => void
  authApiMocks.beginAuthenticatorSetup.mockImplementationOnce(() => new Promise(resolve => { resolveSetup = resolve }))

  renderView()
  fireEvent.click(await screen.findByRole('button', { name: 'Configurar autenticador' }))
  fireEvent.change(screen.getByLabelText('Contraseña actual'), { target: { value: 'synthetic-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Preparar autenticador' }))
  fireEvent.click(screen.getByRole('button', { name: 'Cancelar configuración' }))
  await act(async () => { resolveSetup(syntheticAuthenticator) })
  expect(screen.queryByText(syntheticAuthenticator.secret)).toBeNull()
  expect(screen.queryByLabelText('Código del nuevo autenticador')).toBeNull()
})

it('does not lose one-time backup codes to a report request made before the MFA change', async () => {
  authApiMocks.getAuthStatus.mockResolvedValueOnce({ authenticated: true, csrfToken: 'enrollment-session' })
  authApiMocks.beginAuthenticatorSetup.mockResolvedValueOnce(syntheticAuthenticator)
  let resolveReport!: (value: Response) => void
  let resolveConfirmation!: (value: string[]) => void
  vi.stubGlobal('fetch', vi.fn().mockImplementationOnce(() => new Promise(resolve => { resolveReport = resolve })))
  authApiMocks.confirmAuthenticatorSetup.mockImplementationOnce(() => new Promise(resolve => { resolveConfirmation = resolve }))

  renderView()
  fireEvent.click(await screen.findByRole('button', { name: 'Configurar autenticador' }))
  fireEvent.change(screen.getByLabelText('Contraseña actual'), { target: { value: 'synthetic-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Preparar autenticador' }))
  fireEvent.change(await screen.findByLabelText('Código del nuevo autenticador'), { target: { value: '123456' } })
  fireEvent.click(screen.getByRole('button', { name: 'Confirmar autenticador' }))

  await act(async () => { resolveReport(apiResponse({ detail: 'revoked session' }, 401)) })
  expect(authApiMocks.getAuthStatus).toHaveBeenCalledTimes(1)
  await act(async () => { resolveConfirmation(syntheticRecoveryCodes) })
  expect(screen.getByText(syntheticRecoveryCodes[0])).toBeTruthy()
})

it('offers a keyboard skip link to the main content', () => {
  renderView('/')
  const link = screen.getByRole('link', { name: 'Saltar al contenido principal' })
  expect(link.getAttribute('href')).toBe(`#${screen.getByRole('main').id}`)
  expect(screen.getByRole('main').tabIndex).toBe(-1)
})

it('offers a recovery action when an anonymous session cannot authorize form submissions', async () => {
  authApiMocks.getAuthStatus
    .mockResolvedValueOnce({ authenticated: false, csrfToken: null })
    .mockResolvedValueOnce({ authenticated: false, csrfToken: 'csrf-after-retry' })
  renderView()
  const retry = await screen.findByRole('button', { name: 'Volver a comprobar mi sesión' })
  expect((screen.getByRole('button', { name: 'Iniciar sesión' }) as HTMLButtonElement).disabled).toBe(true)

  fireEvent.click(retry)

  await waitFor(() => expect((screen.getByRole('button', { name: 'Iniciar sesión' }) as HTMLButtonElement).disabled).toBe(false))
  expect(authApiMocks.getAuthStatus).toHaveBeenCalledTimes(2)
})

it('discards an old upload result before requesting analysis for a different session', async () => {
  authApiMocks.getAuthStatus.mockResolvedValueOnce({ authenticated: true, csrfToken: 'first-session' })
  authApiMocks.logout.mockResolvedValue(undefined)
  authApiMocks.login.mockResolvedValue({ authenticated: true, mfaRequired: false, csrfToken: 'next-session' })
  let finishUpload: (response: Response) => void = () => { throw new Error('Upload did not start') }
  const upload = new Promise<Response>((resolve) => { finishUpload = resolve })
  const fetchMock = vi.fn(async (path: string) => {
    if (path === '/v1/reports') return apiResponse({ reports: [] })
    if (path === '/v1/uploads') return upload
    throw new Error('An obsolete upload must not lead to another request')
  })
  vi.stubGlobal('fetch', fetchMock)

  renderView('/#demostracion')
  await screen.findByText('Aún no hay reportes.')
  fireEvent.change(screen.getByLabelText(/Archivo para analizar/), {
    target: { files: [new File(['image'], 'first-account.png', { type: 'image/png' })] },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Subir y analizar' }))
  await screen.findByText('Subiendo archivo…')
  navigateTo('Cuenta')
  fireEvent.click(screen.getByRole('button', { name: 'Cerrar sesión' }))
  await screen.findByText('No hay una sesión iniciada.')
  fireEvent.change(screen.getByLabelText('Correo para iniciar sesión'), { target: { value: 'next@example.test' } })
  fireEvent.change(screen.getByLabelText('Contraseña de la cuenta'), { target: { value: 'synthetic-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
  navigateTo('Archivos y reportes')
  await screen.findByText('Aún no hay reportes.')

  await act(async () => finishUpload(apiResponse({ upload_id: 'first-upload', media_type: 'image/png' }, 201)))
  expect(fetchMock.mock.calls.filter(([path]) => path.startsWith('/v1/analyses'))).toHaveLength(0)
  expect(screen.queryByText('Subiendo archivo…')).toBeNull()
  expect(screen.queryByText(/first-account\.png/)).toBeNull()
})

it('clears completed report details and file status before showing the next session', async () => {
  authApiMocks.getAuthStatus.mockResolvedValueOnce({ authenticated: true, csrfToken: 'first-session' })
  authApiMocks.logout.mockResolvedValue(undefined)
  authApiMocks.login.mockResolvedValue({ authenticated: true, mfaRequired: false, csrfToken: 'next-session' })
  const fetchMock = vi.fn(async (path: string) => {
    if (path === '/v1/reports') return apiResponse({ reports: [] })
    if (path === '/v1/uploads') return apiResponse({ upload_id: 'first-upload', media_type: 'image/png' }, 201)
    if (path === '/v1/analyses/first-upload') return apiResponse(fileReport)
    throw new Error('Unexpected file request')
  })
  vi.stubGlobal('fetch', fetchMock)

  renderView('/#demostracion')
  await screen.findByText('Aún no hay reportes.')
  fireEvent.change(screen.getByLabelText(/Archivo para analizar/), {
    target: { files: [new File(['image'], 'first-account.png', { type: 'image/png' })] },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Subir y analizar' }))
  await screen.findByText('Detalles del reporte')
  expect(screen.getByRole('region', { name: 'Resultado de VirusTotal' })).toBeTruthy()

  navigateTo('Cuenta')
  fireEvent.click(screen.getByRole('button', { name: 'Cerrar sesión' }))
  await screen.findByText('No hay una sesión iniciada.')
  fireEvent.change(screen.getByLabelText('Correo para iniciar sesión'), { target: { value: 'next@example.test' } })
  fireEvent.change(screen.getByLabelText('Contraseña de la cuenta'), { target: { value: 'synthetic-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
  navigateTo('Archivos y reportes')
  await screen.findByText('Aún no hay reportes.')

  expect(screen.queryByText('Detalles del reporte')).toBeNull()
  expect(screen.queryByRole('region', { name: 'Resultado de VirusTotal' })).toBeNull()
  expect(screen.queryByText('Tu reporte está listo. Revisa los detalles o descarga la copia limpia.')).toBeNull()
})

it('runs registration, email verification, password login, MFA, and logout in memory', async () => {
  authApiMocks.getAuthStatus.mockResolvedValueOnce({ authenticated: false, csrfToken: 'csrf-status' })
  authApiMocks.register.mockResolvedValue(undefined)
  authApiMocks.verifyEmail.mockResolvedValue(undefined)
  authApiMocks.login.mockResolvedValueOnce({ authenticated: false, mfaRequired: true, csrfToken: 'csrf-mfa' })
  authApiMocks.completeMfaLogin.mockResolvedValue({ authenticated: true, mfaRequired: false, csrfToken: 'csrf-session' })
  authApiMocks.logout.mockResolvedValue(undefined)
  authApiMocks.getAuthStatus.mockResolvedValueOnce({ authenticated: false, csrfToken: 'csrf-after-logout' })

  renderView()
  expect(await screen.findByText('No hay una sesión iniciada.')).toBeTruthy()

  fireEvent.click(screen.getByRole('button', { name: 'Crear una cuenta' }))
  fireEvent.change(screen.getByLabelText('Correo para registrarte'), { target: { value: 'persona@example.test' } })
  fireEvent.change(screen.getByLabelText('Contraseña nueva'), { target: { value: 'synthetic-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Crear cuenta' }))
  expect(await screen.findByText('Si podemos registrar tu cuenta, recibirás un código por correo. Revisa también la carpeta de correo no deseado.')).toBeTruthy()
  expect(authApiMocks.register).toHaveBeenCalledWith('persona@example.test', 'synthetic-password', 'csrf-status')

  fireEvent.change(screen.getByLabelText('Código de verificación'), { target: { value: 'mail-token' } })
  fireEvent.click(screen.getByRole('button', { name: 'Verificar correo' }))
  expect(await screen.findByText('Correo verificado. Ya puedes iniciar sesión.')).toBeTruthy()
  expect(authApiMocks.verifyEmail).toHaveBeenCalledWith('mail-token', 'csrf-status')

  fireEvent.change(screen.getByLabelText('Correo para iniciar sesión'), { target: { value: 'persona@example.test' } })
  fireEvent.change(screen.getByLabelText('Contraseña de la cuenta'), { target: { value: 'synthetic-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
  expect(await screen.findByText('Confirma tu identidad con tu aplicación de autenticación.')).toBeTruthy()
  expect(screen.queryByLabelText('Contraseña de la cuenta')).toBeNull()

  fireEvent.change(screen.getByLabelText('Contraseña para confirmar el segundo factor'), { target: { value: 're-entered-mfa-password' } })
  fireEvent.change(screen.getByLabelText('Código de autenticación'), { target: { value: '123456' } })
  fireEvent.click(screen.getByRole('button', { name: 'Confirmar segundo factor' }))
  expect(await screen.findByText('Sesión activa.')).toBeTruthy()
  expect(screen.queryByLabelText('Contraseña de la cuenta')).toBeNull()
  expect(authApiMocks.completeMfaLogin).toHaveBeenCalledWith('persona@example.test', 're-entered-mfa-password', '123456', 'csrf-mfa')

  fireEvent.click(screen.getByRole('button', { name: 'Cerrar sesión' }))
  expect(await screen.findByText('Sesión cerrada.')).toBeTruthy()
  expect(authApiMocks.logout).toHaveBeenCalledWith('csrf-session')
})

it('shows unavailable and rate-limit errors without assuming auth is live', async () => {
  authApiMocks.getAuthStatus.mockRejectedValueOnce({ status: 503 })
  renderView()
  expect(await screen.findByText('No pudimos comprobar si tu sesión está abierta.')).toBeTruthy()

  authApiMocks.getAuthStatus.mockResolvedValueOnce({ authenticated: false, csrfToken: 'csrf' })
  authApiMocks.register.mockRejectedValueOnce({ status: 429 })
  authApiMocks.register.mockRejectedValueOnce({ status: 403 })
  fireEvent.click(screen.getByRole('button', { name: 'Volver a comprobar mi sesión' }))
  expect(await screen.findByText('No hay una sesión iniciada.')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Crear una cuenta' }))
  fireEvent.change(screen.getByLabelText('Correo para registrarte'), { target: { value: 'persona@example.test' } })
  fireEvent.change(screen.getByLabelText('Contraseña nueva'), { target: { value: 'synthetic-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Crear cuenta' }))
  expect(await screen.findByText('Has hecho varios intentos. Espera un momento antes de volver a intentarlo.')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Crear cuenta' }))
  expect(await screen.findByText('No pudimos verificar esta solicitud. Recarga la página y vuelve a intentarlo.')).toBeTruthy()
})

it('requires a fresh password when continuing MFA and clears it after submission', async () => {
  authApiMocks.getAuthStatus.mockResolvedValueOnce({ authenticated: false, csrfToken: 'csrf-first' })
  authApiMocks.login.mockResolvedValueOnce({ authenticated: false, mfaRequired: true, csrfToken: 'csrf-challenge' })
  authApiMocks.completeMfaLogin.mockRejectedValueOnce({ status: 401 })

  renderView()
  expect(await screen.findByText('No hay una sesión iniciada.')).toBeTruthy()
  fireEvent.change(screen.getByLabelText('Correo para iniciar sesión'), { target: { value: 'user@example.test' } })
  fireEvent.change(screen.getByLabelText('Contraseña de la cuenta'), { target: { value: 'old-first-factor-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
  expect(await screen.findByText('Confirma tu identidad con tu aplicación de autenticación.')).toBeTruthy()
  expect(screen.queryByLabelText('Contraseña de la cuenta')).toBeNull()

  fireEvent.change(screen.getByLabelText('Código de autenticación'), { target: { value: '123456' } })
  expect(screen.getByLabelText('Contraseña para confirmar el segundo factor')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Confirmar segundo factor' }))
  expect(authApiMocks.completeMfaLogin).not.toHaveBeenCalled()

  fireEvent.change(screen.getByLabelText('Contraseña para confirmar el segundo factor'), { target: { value: 'fresh-mfa-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Confirmar segundo factor' }))
  expect(await screen.findByText('No pudimos confirmar los datos. Revisa el correo, la contraseña o el código e inténtalo de nuevo.')).toBeTruthy()
  expect(authApiMocks.completeMfaLogin).toHaveBeenCalledExactlyOnceWith(
    'user@example.test',
    'fresh-mfa-password',
    '123456',
    'csrf-challenge',
  )
  expect((screen.getByLabelText('Contraseña para confirmar el segundo factor') as HTMLInputElement).value).toBe('')
})
