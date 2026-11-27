import { useRef, useState, type CSSProperties, type KeyboardEvent, type PointerEvent } from 'react'
import { ArrowLeft, ArrowRight, ArrowUpRight, Layers3, MapPin, Minus, ScanLine } from 'lucide-react'
import { viewHref, type NavigateToView } from './viewNavigation'

type Angle = { x: number; y: number }
const flat: Angle = { x: 0, y: 0 }

function bounded(angle: Angle): Angle {
  return { x: Math.max(-28, Math.min(28, angle.x)), y: Math.max(-42, Math.min(42, angle.y)) }
}

export function LivingType({ text }: { text: string }) {
  return <span className="living-type" aria-hidden="true">{text.split(' ').map((word, i) => (
    <span className="type-wrap" key={i}>{i > 0 && ' '}
      <span className="type-word">{Array.from(word).map((letter, index) =>
        <span className="type-letter" key={index}>{letter}</span>)}</span>
    </span>
  ))}</span>
}

export default function PrivacyHero({ authenticated, navigate }: { authenticated: boolean; navigate: NavigateToView }) {
  const [cleaned, setCleaned] = useState(false)
  const [angle, setAngle] = useState(flat)
  const [dragging, setDragging] = useState(false)
  const drag = useRef<{ id: number; startX: number; startY: number; angle: Angle } | null>(null)
  const turn = (x: number, y: number) => setAngle(current => bounded({ x: current.x + x, y: current.y + y }))

  function onKeyDown(event: KeyboardEvent<HTMLElement>) {
    if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return
    switch (event.key) {
      case 'ArrowUp': turn(18, 0); break
      case 'ArrowDown': turn(-18, 0); break
      case 'ArrowLeft': turn(0, -18); break
      case 'ArrowRight': turn(0, 18); break
      case 'Home': setAngle(flat); break
      default: return
    }
    event.preventDefault()
  }

  function startDrag(event: PointerEvent<HTMLDivElement>) {
    if (!event.isPrimary || event.button !== 0) return
    drag.current = { id: event.pointerId, startX: event.clientX, startY: event.clientY, angle }
    event.currentTarget.setPointerCapture?.(event.pointerId)
    setDragging(true)
  }

  function moveDrag(event: PointerEvent<HTMLDivElement>) {
    const start = drag.current
    if (start?.id !== event.pointerId) return
    setAngle(bounded({
      x: start.angle.x - (event.clientY - start.startY) * 0.27,
      y: start.angle.y + (event.clientX - start.startX) * 0.32,
    }))
  }

  function finishDrag(event: PointerEvent<HTMLDivElement>) {
    if (drag.current?.id !== event.pointerId) return
    drag.current = null
    setDragging(false)
  }

  const rotation = { '--turn-x': `${angle.x}deg`, '--turn-y': `${angle.y}deg` } as CSSProperties
  const analysisView = authenticated ? 'files' : 'account'
  return <section className="studio-hero" id="inicio" aria-labelledby="hero-title">
    <div className="studio-inner">
      <div className="studio-copy">
        <div className="cover-label"><span aria-hidden="true">↳</span> Guía de privacidad / 01</div>
        <h1 id="hero-title" aria-label="Comparte el archivo, no su historia."><LivingType text="Comparte el archivo," />{' '}<em><LivingType text="no su historia." /></em></h1>
        <p>Una foto puede revelar dónde estuviste. Un PDF, quién lo creó. Revisa la información oculta y descarga una copia con menos datos personales.</p>
        <div className="studio-actions">
          <a className="primary" href={viewHref(analysisView)} onClick={event => navigate(event, analysisView)}>Analizar un archivo <ArrowUpRight size={18}/></a>
          <a className="text-action" href={viewHref('guide')} onClick={event => navigate(event, 'guide')}>Cómo funciona <ArrowRight size={15}/></a>
        </div>
        <div className="formats"><span>Formatos admitidos</span> JPG <i/> PNG <i/> PDF</div>
      </div>
      <figure className="layer-viewer" aria-label="Explora las capas de un archivo">
        <div className="viewer-top"><span><Layers3 size={16}/> Capas del archivo</span><small>Ejemplo interactivo</small></div>
        <div className="layer-stage" role="group" tabIndex={0} aria-label="Orientación del archivo" aria-describedby="layer-hint"
          onKeyDown={onKeyDown} onPointerDown={startDrag} onPointerMove={moveDrag}
          onPointerUp={finishDrag} onPointerCancel={finishDrag} onLostPointerCapture={finishDrag}
          data-dragging={dragging}>
          <div className="layer-object" style={rotation} data-cleaned={cleaned} aria-hidden="true">
            <div className="layer-plane layer-plane-back" />
            <div className="layer-plane layer-plane-middle" />
          <svg className="print-illustration" viewBox="0 0 540 350" aria-hidden="true" focusable="false" data-version={cleaned ? 'clean' : 'original'}>
            <defs>
              <pattern id="print-hatch" width="10" height="10" patternUnits="userSpaceOnUse" patternTransform="rotate(34)"><path d="M0 0v10" stroke="#191913" strokeWidth="2"/></pattern>
            </defs>
            <g className="paper-stack" stroke="#171714" strokeWidth="4" strokeLinejoin="round">
              <g transform="translate(110 52) rotate(-7 135 104)">
                <rect x="6" y="7" width="270" height="209" fill="#171714"/>
                <rect width="270" height="209" fill="#fffdf5"/>
                <svg x="14" y="14" width="242" height="149" viewBox="0 0 242 149" overflow="hidden">
                  <rect width="242" height="149" fill="#fffdf5" stroke="none"/>
                  <circle cx="176" cy="47" r="23" fill="#ffe600"/>
                  <path d="m-9 112 71-65 78 72 52-51 65 61v27H-9z" fill="url(#print-hatch)"/>
                  <path d="m-9 136 69-44 54 25 29-18 110 49v11H-9z" fill="#7cfc9a"/>
                  <rect x="0" y="0" width="242" height="149" fill="none" strokeWidth="5"/>
                </svg>
                <path d="M14 181h86m-86 10h51" fill="none" strokeWidth="3"/>
                <text x="252" y="191" textAnchor="end" stroke="none" fill="#171714" fontFamily="monospace" fontSize="14" fontWeight="700">FOTO / JPG</text>
              </g>
            </g>
            <g className="print-tag" transform="translate(296 222) rotate(5)">
              <rect x="5" y="6" width="179" height="51" fill="#171714"/>
              <rect width="179" height="51" stroke="#171714" strokeWidth="3" fill={cleaned ? '#7cfc9a' : '#ffe600'}/>
              <path d="M44 1v49" stroke="#171714" strokeWidth="2" strokeDasharray="4 4"/>
              {cleaned ? <path d="m12 25 7 7 13-16" fill="none" stroke="#171714" strokeWidth="4"/> : <g transform="translate(11 12)"><path d="M12 26S2 16 2 10a10 10 0 0 1 20 0c0 6-10 16-10 16Z" fill="#fffdf5" stroke="#171714" strokeWidth="2.5"/><circle cx="12" cy="10" r="3" fill="#171714"/></g>}
              <text x="55" y="31" fill="#171714" fontFamily="monospace" fontSize="16" fontWeight="700">{cleaned ? 'SIN GPS' : 'CON GPS'}</text>
            </g>
          </svg>
          </div>
        </div>
        <figcaption>
          <div className="viewer-toolbar">
            <p id="layer-hint">Arrastra o usa las flechas para girar.</p>
            <div className="viewer-turn" role="group" aria-label="Controles de giro">
              <button type="button" aria-label="Girar a la izquierda" onClick={() => turn(0, -18)}><ArrowLeft size={16} aria-hidden="true" /></button>
              <button type="button" onClick={() => setAngle(flat)}>Centrar vista</button>
              <button type="button" aria-label="Girar a la derecha" onClick={() => turn(0, 18)}><ArrowRight size={16} aria-hidden="true" /></button>
            </div>
          </div>
          <div className="viewer-console">
          <div className="viewer-switch" role="group" aria-label="Comparar versiones del ejemplo">
            <button type="button" aria-pressed={!cleaned} onClick={() => setCleaned(false)}>Original</button>
            <button type="button" aria-pressed={cleaned} onClick={() => setCleaned(true)}>Copia limpia</button>
          </div>
          <p aria-live="polite">{cleaned ? <><Minus size={15}/> Sin ubicación</> : <><MapPin size={15}/> Ubicación incluida</>}</p>
          </div>
        </figcaption>
      </figure>
    </div>
    <div className="hero-baseline"><span><ScanLine size={15}/> Privacidad de archivos</span><span>JPG <b>/</b> PNG <b>/</b> PDF</span></div>
  </section>
}
