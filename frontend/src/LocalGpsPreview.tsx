import { useId, useLayoutEffect, useRef, useState } from 'react'
import { MAX_GPS_FILE_BYTES, parseExifGps, type ExifGpsPoint } from './exifGps'
import { WORLD_LAND_PATH } from './worldLand'
import './LocalGpsPreview.css'

type Preview = { file: File } & (
  | { status: 'reading' | 'no-point' | 'limit' | 'unreadable' }
  | { status: 'point'; point: ExifGpsPoint }
)

const messages = {
  reading: 'Leyendo la ubicación EXIF en este dispositivo…',
  'no-point': 'No se encontró una ubicación GPS EXIF válida en esta imagen.',
  limit: 'La vista local admite archivos de hasta 25 MiB.',
  unreadable: 'No pudimos leer la imagen en este dispositivo.',
}

function WorldPoint({ latitude, longitude }: ExifGpsPoint) {
  const x = (longitude + 180) * 2
  const y = (90 - latitude) * 2
  return (
    <figure className="local-gps-world">
      <svg viewBox="0 0 720 360" role="img" aria-label="Mapa mundial con la ubicación indicada">
        <path className="local-gps-land" d={WORLD_LAND_PATH} fillRule="evenodd" />
        <path className="local-gps-grid" d="M0 60H720M0 120H720M0 180H720M0 240H720M0 300H720M120 0V360M240 0V360M360 0V360M480 0V360M600 0V360" />
        <circle className="local-gps-halo" cx={x} cy={y} r="12" />
        <circle className="local-gps-point" cx={x} cy={y} r="6" />
      </svg>
      <figcaption>
        <strong>{latitude.toFixed(6)}°, {longitude.toFixed(6)}°</strong>
        <span>Coordenadas indicadas por la imagen; no verificadas.</span>
      </figcaption>
    </figure>
  )
}

export default function LocalGpsPreview({ file }: { file: File }) {
  const [preview, setPreview] = useState<Preview | null>(null)
  const version = useRef(0)
  const id = useId()
  useLayoutEffect(() => {
    setPreview(null)
    return () => { version.current++ }
  }, [file])

  if (file.type !== 'image/jpeg' && file.type !== 'image/png') return null
  const current = preview?.file === file ? preview : null

  async function reveal() {
    const request = ++version.current
    if (file.size > MAX_GPS_FILE_BYTES) {
      setPreview({ file, status: 'limit' })
      return
    }
    setPreview({ file, status: 'reading' })
    try {
      const content = await file.arrayBuffer()
      if (request !== version.current) return
      const point = parseExifGps(new Uint8Array(content))
      setPreview(point ? { file, status: 'point', point } : { file, status: 'no-point' })
    } catch {
      if (request === version.current) setPreview({ file, status: 'unreadable' })
    }
  }

  function hide() {
    version.current++
    setPreview(null)
  }

  return (
    <section className="local-gps-preview" aria-labelledby={`${id}-title`}>
      <h3 id={`${id}-title`}>Ubicación de la imagen</h3>
      <p>Esta vista lee los metadatos GPS en tu dispositivo. El mapa no envía ni guarda las coordenadas.</p>
      <button type="button" className="local-gps-toggle" aria-expanded={current !== null}
        aria-controls={`${id}-result`} onClick={current ? hide : () => { void reveal() }}>
        {current ? 'Ocultar ubicación' : 'Revelar GPS en este dispositivo'}
      </button>
      <div id={`${id}-result`} aria-live="polite">
        {current && (current.status === 'point' ? <WorldPoint {...current.point} /> : <p>{messages[current.status]}</p>)}
      </div>
    </section>
  )
}
