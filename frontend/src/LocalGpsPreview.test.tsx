import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import LocalGpsPreview from './LocalGpsPreview'
import { parseExifGps } from './exifGps'

vi.mock('./exifGps', () => ({
  MAX_GPS_FILE_BYTES: 25 * 1024 * 1024,
  parseExifGps: vi.fn(),
}))

function image(name: string, type = 'image/jpeg') {
  const file = new File(['synthetic image'], name, { type })
  const read = vi.fn(async () => new ArrayBuffer(12))
  Object.defineProperty(file, 'arrayBuffer', { value: read })
  return { file, read }
}

const reveal = () => screen.getByRole('button', { name: 'Revelar GPS en este dispositivo' })
const hide = () => screen.getByRole('button', { name: 'Ocultar ubicación' })
const map = () => screen.queryByRole('img', { name: 'Mapa mundial con la ubicación indicada' })

beforeEach(() => {
  vi.mocked(parseExifGps).mockReset().mockReturnValue({ latitude: 19.4326, longitude: -99.1332 })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('private GPS preview', () => {
  it('does not read, reveal, or issue network requests until explicitly asked to read locally', async () => {
    const fetch = vi.fn()
    vi.stubGlobal('fetch', fetch)
    const { file, read } = image('sample.jpg')
    render(<LocalGpsPreview file={file} />)
    expect(read).not.toHaveBeenCalled()
    expect(map()).toBeNull()
    fireEvent.click(reveal())
    await screen.findByRole('img', { name: 'Mapa mundial con la ubicación indicada' })
    expect(read).toHaveBeenCalledTimes(1)
    expect(screen.getByText('19.432600°, -99.133200°')).toBeTruthy()
    expect(fetch).not.toHaveBeenCalled()
    fireEvent.click(hide())
    expect(map()).toBeNull()
    expect(screen.queryByText('19.432600°, -99.133200°')).toBeNull()
  })

  it('does not read unsupported or oversized files', async () => {
    const pdf = image('document.pdf', 'application/pdf')
    const view = render(<LocalGpsPreview file={pdf.file} />)
    expect(screen.queryByRole('button')).toBeNull()

    const { file, read } = image('oversized.png', 'image/png')
    Object.defineProperty(file, 'size', { value: 25 * 1024 * 1024 + 1 })
    view.rerender(<LocalGpsPreview file={file} />)
    fireEvent.click(reveal())
    await screen.findByText('La vista local admite archivos de hasta 25 MiB.')
    expect(read).not.toHaveBeenCalled()
    expect(pdf.read).not.toHaveBeenCalled()
  })

  it('discards a late read when the selected file changes or the view is hidden', async () => {
    const first = image('one.jpg')
    const second = image('two.png', 'image/png')
    let resolve = (_: ArrayBuffer) => {}
    first.read.mockReturnValueOnce(new Promise<ArrayBuffer>(done => { resolve = done }))
    const view = render(<LocalGpsPreview file={first.file} />)
    fireEvent.click(reveal())
    view.rerender(<LocalGpsPreview file={second.file} />)

    await act(async () => { resolve(new ArrayBuffer(12)) })
    expect(map()).toBeNull()
    expect(parseExifGps).not.toHaveBeenCalled()

    second.read.mockReturnValueOnce(new Promise<ArrayBuffer>(done => { resolve = done }))
    fireEvent.click(reveal())
    fireEvent.click(hide())
    await act(async () => { resolve(new ArrayBuffer(12)) })
    expect(map()).toBeNull()
    expect(parseExifGps).not.toHaveBeenCalled()
  })

  it('keeps replaced coordinates hidden even if the same File is reselected', async () => {
    const first = image('one.jpg')
    const second = image('two.png', 'image/png')
    const view = render(<LocalGpsPreview file={first.file} />)
    fireEvent.click(reveal())
    await screen.findByRole('img', { name: 'Mapa mundial con la ubicación indicada' })
    view.rerender(<LocalGpsPreview file={second.file} />)
    view.rerender(<LocalGpsPreview file={first.file} />)
    expect(map()).toBeNull()
    expect(reveal()).toBeTruthy()
  })

  it('states when metadata does not give a valid GPS location', async () => {
    vi.mocked(parseExifGps).mockReturnValueOnce(null)
    const { file } = image('no-gps.jpg')
    render(<LocalGpsPreview file={file} />)
    fireEvent.click(reveal())
    await screen.findByText('No se encontró una ubicación GPS EXIF válida en esta imagen.')
    expect(map()).toBeNull()
  })
})
