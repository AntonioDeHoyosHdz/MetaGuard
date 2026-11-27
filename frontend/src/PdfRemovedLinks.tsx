import { useId, useState } from 'react'
import './PdfRemovedLinks.css'

export default function PdfRemovedLinks({ destinations, removedCount }: {
  destinations: string[]
  removedCount: number
}) {
  const [revealed, setRevealed] = useState(false)
  const id = useId()
  if (removedCount === 0) return null
  if (destinations.length === 0) {
    return <p>No hay destinos retirados que se puedan mostrar de forma segura.</p>
  }

  const notShown = removedCount - destinations.length
  return (
    <div className="pdf-removed-links">
      <button type="button" className="auth-button auth-secondary" aria-controls={id} aria-expanded={revealed}
        onClick={() => setRevealed((current) => !current)}>
        {revealed ? 'Ocultar destinos retirados' : 'Mostrar destinos retirados'}
      </button>
      <div id={id}>
        {revealed && <>
          <p>Lista temporal de destinos HTTP(S), sin parámetros de consulta ni fragmentos. No se abren ni se consultan.</p>
          <ul className="pdf-removed-links__list">
            {destinations.map((destination) => <li key={destination}><code>{destination}</code></li>)}
          </ul>
          {notShown > 0 && <p>Sin una vista adicional: {notShown}. Incluye destinos repetidos u omitidos por seguridad.</p>}
        </>}
      </div>
    </div>
  )
}
