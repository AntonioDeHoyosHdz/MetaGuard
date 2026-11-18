import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import App from './App'

vi.mock('./Scene', () => ({ default: () => <div data-testid="scene" /> }))
beforeEach(() => {
  vi.resetAllMocks()
  authApiMocks.getAuthStatus.mockResolvedValue({ authenticated: false, csrfToken: 'csrf-test' })
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('MetaGuard visual demonstration', () => {
  it('identifies the page as a demonstration without uploading files', () => {
    const { container } = render(<App />)
    expect(screen.getByText('Diseño de demostración. Sin procesamiento real.')).toBeTruthy()
    expect(screen.getByText('El análisis y la limpieza aún no están conectados.')).toBeTruthy()
    expect(container.querySelector('input[type="file"]')).toBeNull()
  })

  it('switches between example risk categories accessibly', () => {
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: '3. Resultado de ejemplo' }))
    const medium = screen.getByRole('button', { name: 'Riesgo medio' })
    fireEvent.click(medium)
    expect(medium.getAttribute('aria-pressed')).toBe('true')
    expect(screen.getByText('Dispositivo')).toBeTruthy()
    expect(screen.queryByText('Ubicación GPS')).toBeNull()
  })

  it('moves through simulated stages and restarts without real files', () => {
    const { container } = render(<App />)
    fireEvent.click(screen.getByRole('button', { name: 'Continuar al análisis de ejemplo' }))
    expect(screen.getByText(/No se ha recibido un archivo/)).toBeTruthy()
    expect(document.activeElement).toBe(screen.getByText(/No se ha recibido un archivo/).closest('.demo-stage'))
    fireEvent.click(screen.getByRole('button', { name: 'Ver resultado de ejemplo' }))
    expect(screen.getByText('Datos ficticios; no son el resultado de un análisis real.')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Reiniciar ejemplo' }))
    expect(screen.getByText(/Ningún archivo se ha seleccionado/)).toBeTruthy()
    expect(container.querySelector('input[type="file"]')).toBeNull()
  })

  it('opens and closes the navigation menu', () => {
    render(<App />)
    const button = screen.getByRole('button', { name: 'Abrir menú' })
    fireEvent.click(button)
    expect(screen.getByRole('button', { name: 'Cerrar menú' }).getAttribute('aria-expanded')).toBe('true')
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(screen.getByRole('button', { name: 'Abrir menú' }).getAttribute('aria-expanded')).toBe('false')
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Abrir menú' }))
  })
})

it('reports API and database readiness without claiming file processing', async () => {
  const request = vi.fn()
    .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'ok' }) })
    .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'ok' }) })
  vi.stubGlobal('fetch', request)
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: 'Comprobar API' }))
  expect(await screen.findByText('API y base de datos disponibles; procesamiento de archivos aún no conectado.')).toBeTruthy()
  expect(request).toHaveBeenNthCalledWith(1, '/health/live', expect.objectContaining({ credentials: 'omit', cache: 'no-store' }))
  expect(request).toHaveBeenNthCalledWith(2, '/health/ready', expect.objectContaining({ credentials: 'omit', cache: 'no-store' }))
  vi.unstubAllGlobals()
})

it('reports an unavailable API without pretending analysis worked', async () => {
  const request = vi.fn().mockRejectedValue(new Error('offline'))
  vi.stubGlobal('fetch', request)
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: 'Comprobar API' }))
  expect(await screen.findByText('No se pudo comprobar la API.')).toBeTruthy()
  expect(request).toHaveBeenCalledTimes(1)
  vi.unstubAllGlobals()
})

it('rejects an unexpected API response and allows retry', async () => {
  const request = vi.fn()
    .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'unexpected' }) })
    .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'ok' }) })
    .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'ok' }) })
  vi.stubGlobal('fetch', request)
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: 'Comprobar API' }))
  expect(await screen.findByText('No se pudo comprobar la API.')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Comprobar API' }))
  expect(await screen.findByText('API y base de datos disponibles; procesamiento de archivos aún no conectado.')).toBeTruthy()
  expect(request).toHaveBeenCalledTimes(3)
  vi.unstubAllGlobals()
})

it('reports database unavailability separately after API liveness succeeds', async () => {
  const request = vi.fn()
    .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'ok' }) })
    .mockResolvedValueOnce({ ok: false, json: async () => ({ status: 'unavailable' }) })
  vi.stubGlobal('fetch', request)
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: 'Comprobar API' }))
  expect(await screen.findByText('API disponible; base de datos no disponible.')).toBeTruthy()
  expect(request).toHaveBeenCalledTimes(2)
  vi.unstubAllGlobals()
})
const authApiMocks = vi.hoisted(() => ({
  getAuthStatus: vi.fn(),
  register: vi.fn(),
  verifyEmail: vi.fn(),
  login: vi.fn(),
  completeMfaLogin: vi.fn(),
  logout: vi.fn(),
}))

vi.mock('./authApi', () => authApiMocks)

it('runs registration, email verification, password login, MFA, and logout in memory', async () => {
  authApiMocks.getAuthStatus.mockResolvedValueOnce({ authenticated: false, csrfToken: 'csrf-status' })
  authApiMocks.register.mockResolvedValue(undefined)
  authApiMocks.verifyEmail.mockResolvedValue(undefined)
  authApiMocks.login.mockResolvedValueOnce({ authenticated: false, mfaRequired: true, csrfToken: 'csrf-mfa' })
  authApiMocks.completeMfaLogin.mockResolvedValue({ authenticated: true, mfaRequired: false, csrfToken: 'csrf-session' })
  authApiMocks.logout.mockResolvedValue(undefined)
  authApiMocks.getAuthStatus.mockResolvedValueOnce({ authenticated: false, csrfToken: 'csrf-after-logout' })

  render(<App />)
  expect(await screen.findByText('No hay una sesión iniciada.')).toBeTruthy()

  fireEvent.change(screen.getByLabelText('Correo para registrarte'), { target: { value: 'persona@example.test' } })
  fireEvent.change(screen.getByLabelText('Contraseña nueva'), { target: { value: 'synthetic-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Crear cuenta' }))
  expect(await screen.findByText('Si el registro fue aceptado, recibirás instrucciones por correo.')).toBeTruthy()
  expect(authApiMocks.register).toHaveBeenCalledWith('persona@example.test', 'synthetic-password', 'csrf-status')

  fireEvent.change(screen.getByLabelText('Token de verificación'), { target: { value: 'mail-token' } })
  fireEvent.click(screen.getByRole('button', { name: 'Verificar correo' }))
  expect(await screen.findByText('Correo verificado. Ya podés iniciar sesión.')).toBeTruthy()
  expect(authApiMocks.verifyEmail).toHaveBeenCalledWith('mail-token', 'csrf-status')

  fireEvent.change(screen.getByLabelText('Correo para iniciar sesión'), { target: { value: 'persona@example.test' } })
  fireEvent.change(screen.getByLabelText('Contraseña de la cuenta'), { target: { value: 'synthetic-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
  expect(await screen.findByText('Se requiere el segundo factor para continuar.')).toBeTruthy()
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
  render(<App />)
  expect(await screen.findByText('No se pudo consultar el estado de sesión. El servicio de autenticación puede no estar disponible.')).toBeTruthy()

  authApiMocks.getAuthStatus.mockResolvedValueOnce({ authenticated: false, csrfToken: 'csrf' })
  authApiMocks.register.mockRejectedValueOnce({ status: 429 })
  authApiMocks.register.mockRejectedValueOnce({ status: 403 })
  fireEvent.click(screen.getByRole('button', { name: 'Reintentar estado de sesión' }))
  expect(await screen.findByText('No hay una sesión iniciada.')).toBeTruthy()
  fireEvent.change(screen.getByLabelText('Correo para registrarte'), { target: { value: 'persona@example.test' } })
  fireEvent.change(screen.getByLabelText('Contraseña nueva'), { target: { value: 'synthetic-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Crear cuenta' }))
  expect(await screen.findByText('Hay demasiados intentos. Esperá un momento antes de volver a probar.')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Crear cuenta' }))
  expect(await screen.findByText('No se pudo validar el origen o la protección de seguridad.')).toBeTruthy()
})

it('requires a fresh password when continuing MFA and clears it after submission', async () => {
  authApiMocks.getAuthStatus.mockResolvedValueOnce({ authenticated: false, csrfToken: 'csrf-first' })
  authApiMocks.login.mockResolvedValueOnce({ authenticated: false, mfaRequired: true, csrfToken: 'csrf-challenge' })
  authApiMocks.completeMfaLogin.mockRejectedValueOnce({ status: 401 })

  render(<App />)
  expect(await screen.findByText('No hay una sesión iniciada.')).toBeTruthy()
  fireEvent.change(screen.getByLabelText('Correo para iniciar sesión'), { target: { value: 'user@example.test' } })
  fireEvent.change(screen.getByLabelText('Contraseña de la cuenta'), { target: { value: 'old-first-factor-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
  expect(await screen.findByText('Se requiere el segundo factor para continuar.')).toBeTruthy()
  expect(screen.queryByLabelText('Contraseña de la cuenta')).toBeNull()

  fireEvent.change(screen.getByLabelText('Código de autenticación'), { target: { value: '123456' } })
  expect(screen.getByLabelText('Contraseña para confirmar el segundo factor')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Confirmar segundo factor' }))
  expect(authApiMocks.completeMfaLogin).not.toHaveBeenCalled()

  fireEvent.change(screen.getByLabelText('Contraseña para confirmar el segundo factor'), { target: { value: 'fresh-mfa-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Confirmar segundo factor' }))
  expect(await screen.findByText('No se pudieron validar las credenciales o el código.')).toBeTruthy()
  expect(authApiMocks.completeMfaLogin).toHaveBeenCalledExactlyOnceWith(
    'user@example.test',
    'fresh-mfa-password',
    '123456',
    'csrf-challenge',
  )
  expect((screen.getByLabelText('Contraseña para confirmar el segundo factor') as HTMLInputElement).value).toBe('')
})
