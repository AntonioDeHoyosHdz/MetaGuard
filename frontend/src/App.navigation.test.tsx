import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import App from './App'
import * as auth from './authApi'
import * as files from './fileApi'

vi.mock('./authApi')
vi.mock('./fileApi', async (original) => ({ ...await original<typeof files>(), getReports: vi.fn() }))

const guest = { authenticated: false, csrfToken: 'synthetic-guest' }
const active = { authenticated: true, csrfToken: 'synthetic-session' }
const nav = () => within(screen.getByRole('navigation', { name: 'Navegación principal' }))
const open = (name: string) => fireEvent.click(nav().getByRole('link', { name }))

beforeEach(() => {
  vi.resetAllMocks()
  window.history.replaceState(null, '', '/')
  vi.mocked(auth.getAuthStatus).mockResolvedValue(guest)
  vi.mocked(files.getReports).mockResolvedValue([])
})

afterEach(() => { cleanup(); window.history.replaceState(null, '', '/') })

it('only mounts the active view and marks it in the navigation', async () => {
  render(<App />)
  const views = [
    ['Inicio', /Comparte el archivo, no su historia/i, '#inicio'],
    ['Cómo funciona', /Del original a la copia/i, '#como-funciona'],
    ['Archivos y reportes', /Tus archivos y reportes/i, '#demostracion'],
    ['Cuenta', /Tu espacio privado/i, '#cuenta'],
    ['Privacidad', /Comparte con más confianza/i, '#privacidad'],
  ] as const

  for (const [name, heading, hash] of views) {
    open(name)
    const main = screen.getByRole('main')
    expect(within(main).getByRole('heading', { name: heading })).toBeTruthy()
    expect(window.location.hash).toBe(hash)
    expect(document.activeElement).toBe(main)
    expect(nav().getAllByRole('link').filter((link) => link.getAttribute('aria-current') === 'page'))
      .toEqual([nav().getByRole('link', { name })])
    for (const [other, inactive] of views) {
      if (other !== name) expect(screen.queryByRole('heading', { name: inactive })).toBeNull()
    }
  }
})

it('reopens a legacy deep link and agrees with the browser Back and Forward buttons', async () => {
  window.history.replaceState(null, '', '/#como-funciona')
  const initial = render(<App />)
  expect(nav().getByRole('link', { name: 'Cómo funciona' }).getAttribute('aria-current')).toBe('page')
  open('Archivos y reportes')
  expect(await screen.findByText(/Inicia sesión para subir archivos/)).toBeTruthy()
  window.history.back()
  await waitFor(() => expect(nav().getByRole('link', { name: 'Cómo funciona' }).getAttribute('aria-current')).toBe('page'))
  window.history.forward()
  await waitFor(() => expect(window.location.hash).toBe('#demostracion'))
  await waitFor(() => expect(nav().getByRole('link', { name: 'Archivos y reportes' }).getAttribute('aria-current')).toBe('page'))
  initial.unmount()
  render(<App />)
  expect(await screen.findByText(/Inicia sesión para subir archivos/)).toBeTruthy()
  expect(screen.queryByRole('heading', { name: /Del original a la copia/i })).toBeNull()
})

it('moves focus out of the mobile menu and skips to content without changing the active address', async () => {
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: 'Abrir menú' }))
  open('Cómo funciona')
  const main = screen.getByRole('main')
  expect(screen.getByRole('button', { name: 'Abrir menú' }).getAttribute('aria-expanded')).toBe('false')
  expect(document.activeElement).toBe(main)
  fireEvent.click(screen.getByRole('link', { name: 'Saltar al contenido principal' }))
  expect(window.location.hash).toBe('#como-funciona')
  expect(document.activeElement).toBe(main)
  await waitFor(() => expect(auth.getAuthStatus).toHaveBeenCalledOnce())
})

it('offers sign-in on the legacy history address without exposing data or controls to visitors', async () => {
  window.history.replaceState(null, '', '/security/events#actividad')
  vi.mocked(auth.login).mockResolvedValue({ authenticated: true, mfaRequired: false, csrfToken: active.csrfToken })
  vi.mocked(auth.getSecurityEvents).mockResolvedValue([])
  render(<App />)
  expect(await screen.findByText('Inicia sesión para consultar la actividad de seguridad de tu cuenta.')).toBeTruthy()
  expect(auth.getSecurityEvents).not.toHaveBeenCalled()
  expect(screen.queryByRole('link', { name: 'Ocultar actividad de seguridad' })).toBeNull()
  expect(screen.queryByLabelText(/Archivo para analizar/)).toBeNull()
  fireEvent.change(screen.getByLabelText('Correo para iniciar sesión'), { target: { value: 'test@example.test' } })
  fireEvent.change(screen.getByLabelText('Contraseña de la cuenta'), { target: { value: 'synthetic-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
  expect(await screen.findByText('No hay eventos recientes.')).toBeTruthy()
  expect(auth.getSecurityEvents).toHaveBeenCalledExactlyOnceWith(active.csrfToken)
  open('Privacidad')
  expect(window.location.pathname).toBe('/')
  expect(screen.queryByRole('heading', { name: 'Actividad de seguridad' })).toBeNull()
})

it('clears unused passwords on view changes, without saving credentials in browser history', async () => {
  window.history.replaceState(null, '', '/#cuenta')
  render(<App />)
  const password = await screen.findByLabelText('Contraseña de la cuenta')
  fireEvent.change(password, { target: { value: 'synthetic-password' } })
  open('Privacidad')
  expect(screen.queryByLabelText('Contraseña de la cuenta')).toBeNull()
  expect(window.history.state).toBeNull()
  open('Cuenta')
  expect((screen.getByLabelText('Contraseña de la cuenta') as HTMLInputElement).value).toBe('')
})

it('keeps a file draft within the session and invalidates it even outside the file view', async () => {
  window.history.replaceState(null, '', '/#demostracion')
  vi.mocked(auth.getAuthStatus).mockResolvedValue(active)
  render(<App />)
  const input = await screen.findByLabelText(/Archivo para analizar/)
  fireEvent.change(input, { target: { files: [new File(['test'], 'private-a.png', { type: 'image/png' })] } })
  open('Privacidad')
  expect(screen.queryByText(/private-a.png/)).toBeNull()
  open('Archivos y reportes')
  expect(screen.getByText(/Archivo seleccionado: private-a.png/)).toBeTruthy()
  open('Privacidad')
  act(() => window.dispatchEvent(new StorageEvent('storage', { key: 'metaguard.session-invalidation', newValue: 'lock' })))
  open('Archivos y reportes')
  expect(screen.queryByText(/private-a.png/)).toBeNull()
  expect(screen.queryByLabelText(/Archivo para analizar/)).toBeNull()
})

it('identifies a missing password reset endpoint without claiming that a reset message was sent', async () => {
  window.history.replaceState(null, '', '/#cuenta')
  vi.mocked(auth.requestPasswordReset).mockRejectedValue({ status: 404 })
  render(<App />)
  fireEvent.click(await screen.findByRole('button', { name: 'Olvidé mi contraseña' }))
  fireEvent.change(screen.getByLabelText('Correo de tu cuenta'), { target: { value: 'test@example.test' } })
  fireEvent.click(screen.getByRole('button', { name: 'Pedir código de recuperación' }))
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'Esta función no está disponible en el servidor conectado.')
  expect(screen.queryByText(/podrás recibir un código/)).toBeNull()
})

it('distinguishes a missing activity endpoint from an expired session', async () => {
  window.history.replaceState(null, '', '/security/events')
  vi.mocked(auth.getAuthStatus).mockResolvedValueOnce(active)
  vi.mocked(auth.getSecurityEvents).mockRejectedValue({ status: 404 })
  render(<App />)
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'Esta función no está disponible en el servidor conectado.')
  expect(screen.getByText('Sesión activa.')).toBeTruthy()
  expect(auth.getAuthStatus).toHaveBeenCalledOnce()
})

it('delivers one-time recovery codes after authenticator confirmation finishes outside the account view', async () => {
  window.history.replaceState(null, '', '/#cuenta')
  vi.mocked(auth.getAuthStatus).mockResolvedValueOnce(active)
  vi.mocked(auth.beginAuthenticatorSetup).mockResolvedValue({ secret: 'SYNTHETIC', expiresAt: 4_102_444_800 })
  let finish!: (codes: string[]) => void
  vi.mocked(auth.confirmAuthenticatorSetup).mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
  render(<App />)
  fireEvent.click(await screen.findByRole('button', { name: 'Configurar autenticador' }))
  fireEvent.change(screen.getByLabelText('Contraseña actual'), { target: { value: 'synthetic-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Preparar autenticador' }))
  fireEvent.change(await screen.findByLabelText('Código del nuevo autenticador'), { target: { value: '123456' } })
  fireEvent.click(screen.getByRole('button', { name: 'Confirmar autenticador' }))
  open('Privacidad')
  expect(screen.queryByText('SYNTHETIC')).toBeNull()
  const code = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  await act(async () => finish([code]))
  expect(screen.queryByText(code)).toBeNull()
  open('Cuenta')
  expect(screen.getByText(code)).toBeTruthy()
})
