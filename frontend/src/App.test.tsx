import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import App from './App'

vi.mock('./Scene', () => ({ default: () => <div data-testid="scene" /> }))
afterEach(cleanup)

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

it('reports real API liveness without claiming file processing', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ status: 'ok' }) }))
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: 'Comprobar API' }))
  expect(await screen.findByText('API disponible; procesamiento de archivos aún no conectado.')).toBeTruthy()
  expect(fetch).toHaveBeenCalledWith('/health/live', expect.objectContaining({ credentials: 'omit' }))
  vi.unstubAllGlobals()
})

it('reports an unavailable API without pretending analysis worked', async () => {
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')))
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: 'Comprobar API' }))
  expect(await screen.findByText('No se pudo comprobar la API.')).toBeTruthy()
  vi.unstubAllGlobals()
})

it('rejects an unexpected API response and allows retry', async () => {
  const request = vi.fn()
    .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'unexpected' }) })
    .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'ok' }) })
  vi.stubGlobal('fetch', request)
  render(<App />)
  fireEvent.click(screen.getByRole('button', { name: 'Comprobar API' }))
  expect(await screen.findByText('No se pudo comprobar la API.')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Comprobar API' }))
  expect(await screen.findByText('API disponible; procesamiento de archivos aún no conectado.')).toBeTruthy()
  vi.unstubAllGlobals()
})
