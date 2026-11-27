import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import App from './App'
import * as auth from './authApi'
import * as files from './fileApi'

vi.mock('./authApi')
vi.mock('./fileApi', async (original) => ({ ...await original<typeof files>(), getReports: vi.fn(), uploadFile: vi.fn() }))

const sent = vi.fn()
let receive: (event: MessageEvent) => void
class Channel {
  set onmessage(listener: (event: MessageEvent) => void) { receive = listener }
  postMessage = sent
  close = vi.fn()
}

const active = { authenticated: true, csrfToken: 'synthetic-session' }
const anon = { authenticated: false, csrfToken: 'synthetic-guest' }
beforeEach(() => {
  vi.resetAllMocks()
  vi.stubGlobal('BroadcastChannel', Channel)
  vi.mocked(auth.getAuthStatus).mockResolvedValue(active)
  vi.mocked(files.getReports).mockResolvedValue([])
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); window.history.replaceState(null, '', '/') })

function navigateTo(name: string) {
  fireEvent.click(within(screen.getByRole('navigation', { name: 'Navegación principal' })).getByRole('link', { name }))
}

async function selectPrivateFile() {
  window.history.replaceState(null, '', '/#demostracion')
  render(<App />)
  await screen.findByText('Aún no hay reportes.')
  fireEvent.change(screen.getByLabelText(/Archivo para analizar/), {
    target: { files: [new File(['test'], 'private-a.png', { type: 'image/png' })] },
  })
  expect(screen.getByText(/Archivo seleccionado: private-a/)).toBeTruthy()
}

it.each(['changed', 'pageshow'])('clears private data before awaiting status on %s', async (event) => {
  await selectPrivateFile()
  let finish!: (result: typeof anon) => void
  vi.mocked(auth.getAuthStatus).mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
  act(() => {
    if (event === 'changed') receive(new MessageEvent('message', { data: 'changed' }))
    else window.dispatchEvent(Object.assign(new Event('pageshow'), { persisted: true }))
  })
  expect(screen.queryByText(/Archivo seleccionado: private-a/)).toBeNull()
  expect(screen.queryByLabelText(/Archivo para analizar/)).toBeNull()
  await act(async () => finish(anon))
  navigateTo('Cuenta')
  expect(screen.getByText('No hay una sesión iniciada.')).toBeTruthy()
  expect(sent).not.toHaveBeenCalled()
})

it('does not disclose private state or claim success after a failed logout', async () => {
  await selectPrivateFile()
  let reject!: () => void
  vi.mocked(auth.logout).mockImplementationOnce(() => new Promise((_resolve, fail) => { reject = () => fail(new Error('offline')) }))
  navigateTo('Cuenta')
  fireEvent.click(screen.getByRole('button', { name: 'Cerrar sesión' }))
  navigateTo('Archivos y reportes')
  expect(screen.queryByLabelText(/Archivo para analizar/)).toBeNull()
  expect(sent.mock.calls).toEqual([['lock']])
  await act(async () => reject())
  navigateTo('Cuenta')
  expect(screen.getByRole('button', { name: 'Volver a comprobar mi sesión' })).toBeTruthy()
  expect(screen.queryByText('Sesión cerrada.')).toBeNull()
  navigateTo('Archivos y reportes')
  expect(screen.queryByText(/Archivo seleccionado: private-a/)).toBeNull()
})

it('locks the previous workspace on a stale CSRF response and bounds status rechecks', async () => {
  await selectPrivateFile()
  vi.mocked(files.uploadFile).mockRejectedValueOnce({ status: 403 })
  vi.mocked(files.getReports).mockRejectedValue({ status: 403 })
  fireEvent.click(screen.getByRole('button', { name: 'Subir y analizar' }))
  navigateTo('Cuenta')
  await screen.findByRole('button', { name: 'Volver a comprobar mi sesión' })
  navigateTo('Archivos y reportes')
  expect(screen.queryByText(/Archivo seleccionado: private-a/)).toBeNull()
  expect(auth.getAuthStatus).toHaveBeenCalledTimes(2)
  expect(files.getReports).toHaveBeenCalledTimes(2)
})

it('does not discard authenticator setup when returning from another app', async () => {
  vi.mocked(auth.beginAuthenticatorSetup).mockResolvedValue({ secret: 'SYNTHETIC', expiresAt: 4_102_444_800 })
  await selectPrivateFile()
  navigateTo('Cuenta')
  fireEvent.click(screen.getByRole('button', { name: 'Configurar autenticador' }))
  fireEvent.change(screen.getByLabelText('Contraseña actual'), { target: { value: 'synthetic-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Preparar autenticador' }))
  await screen.findByText('SYNTHETIC')
  fireEvent(window, new Event('focus'))
  fireEvent(document, new Event('visibilitychange'))
  fireEvent(window, Object.assign(new Event('pageshow'), { persisted: false }))
  expect(screen.getByText('SYNTHETIC')).toBeTruthy()
  expect(auth.getAuthStatus).toHaveBeenCalledTimes(1)
})

it('keeps another tab locked until logout finishes and never rebroadcasts a received event', async () => {
  await selectPrivateFile()
  act(() => receive(new MessageEvent('message', { data: { authenticated: true } })))
  expect(screen.getByText(/Archivo seleccionado: private-a/)).toBeTruthy()
  act(() => receive(new MessageEvent('message', { data: 'lock' })))
  expect(screen.queryByLabelText(/Archivo para analizar/)).toBeNull()
  expect(auth.getAuthStatus).toHaveBeenCalledTimes(1)
  vi.mocked(auth.getAuthStatus).mockResolvedValueOnce(anon)
  act(() => receive(new MessageEvent('message', { data: 'changed' })))
  navigateTo('Cuenta')
  await screen.findByText('No hay una sesión iniciada.')
  expect(sent).not.toHaveBeenCalled()
})

it('clears enrollment and its containing workspace on a 403 during preparation', async () => {
  vi.mocked(auth.beginAuthenticatorSetup).mockRejectedValue({ status: 403 })
  await selectPrivateFile()
  vi.mocked(auth.getAuthStatus).mockResolvedValueOnce(anon)
  navigateTo('Cuenta')
  fireEvent.click(screen.getByRole('button', { name: 'Configurar autenticador' }))
  fireEvent.change(screen.getByLabelText('Contraseña actual'), { target: { value: 'synthetic-password' } })
  fireEvent.click(screen.getByRole('button', { name: 'Preparar autenticador' }))
  await screen.findByText('No hay una sesión iniciada.')
  expect(screen.queryByLabelText('Contraseña actual')).toBeNull()
  navigateTo('Archivos y reportes')
  expect(screen.queryByText(/Archivo seleccionado: private-a/)).toBeNull()
})

it('sends only fixed notices and establishes fresh anonymous status before waking peers', async () => {
  await selectPrivateFile()
  let finish!: (value: typeof anon) => void
  vi.mocked(auth.getAuthStatus).mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
  vi.mocked(auth.logout).mockResolvedValueOnce(undefined)
  navigateTo('Cuenta')
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Cerrar sesión' })) })
  expect(sent.mock.calls).toEqual([['lock']])
  await act(async () => finish(anon))
  expect(sent.mock.calls).toEqual([['lock'], ['changed']])
})
