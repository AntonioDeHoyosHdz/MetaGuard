import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import {
  ArrowDown, ArrowRight, ArrowUpRight, Check, ChevronDown, CircleHelp,
  FileImage, Fingerprint, Layers3, LockKeyhole, MapPin, Menu, ScanLine,
  Shield, ShieldCheck, Sparkles, X,
} from 'lucide-react'
import './App.css'

const Scene = lazy(() => import('./Scene'))

type Risk = 'Alto' | 'Medio' | 'Bajo'
type DemoStep = 'carga' | 'analisis' | 'resultado'

const demoSteps: { id: DemoStep; number: string; label: string }[] = [
  { id: 'carga', number: '01', label: 'Carga' },
  { id: 'analisis', number: '02', label: 'Análisis' },
  { id: 'resultado', number: '03', label: 'Resultado' },
]

const example: Record<Risk, { label: string; detail: string; icon: typeof MapPin }[]> = {
  Alto: [
    { label: 'Ubicación GPS', detail: 'Puede revelar dónde se tomó una imagen.', icon: MapPin },
    { label: 'Autoría', detail: 'Puede identificar a la persona que creó el archivo.', icon: Fingerprint },
  ],
  Medio: [
    { label: 'Dispositivo', detail: 'Puede revelar el modelo utilizado.', icon: FileImage },
    { label: 'Software', detail: 'Puede mostrar la herramienta de edición.', icon: Layers3 },
  ],
  Bajo: [
    { label: 'Dimensiones', detail: 'Describen el tamaño de la imagen.', icon: ScanLine },
  ],
}

const steps = [
  { n: '01', icon: FileImage, title: 'Elige un archivo', text: 'JPG, PNG o PDF. Una forma sencilla de empezar a entender lo que compartes.' },
  { n: '02', icon: ScanLine, title: 'Conoce sus datos', text: 'Visualiza qué información puede viajar junto a tu archivo y por qué importa.' },
  { n: '03', icon: ShieldCheck, title: 'Comparte con intención', text: 'El objetivo es darte más claridad antes de compartir. La limpieza aún está en desarrollo.' },
]

function App() {
  const [risk, setRisk] = useState<Risk>('Alto')
  const [demoStep, setDemoStep] = useState<DemoStep>('carga')
  const [focusDemoStage, setFocusDemoStage] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const demoStage = useRef<HTMLDivElement>(null)
  const menuButton = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (focusDemoStage) {
      demoStage.current?.focus()
      setFocusDemoStage(false)
    }
  }, [demoStep, focusDemoStage])

  const showDemoStep = (step: DemoStep) => {
    setDemoStep(step)
    setFocusDemoStage(true)
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

  return (
    <div className="app-shell">
      <header className="site-header">
        <a className="brand" href="#inicio" aria-label="MetaGuard, ir al inicio">
          <span className="brand-mark"><ShieldCheck size={19} strokeWidth={2} /></span>
          <span>meta<span className="brand-light">guard</span><span className="brand-dot">.</span></span>
        </a>
        <nav className={`main-nav ${menuOpen ? 'is-open' : ''}`} aria-label="Navegación principal">
          <a href="#inicio" onClick={() => setMenuOpen(false)}>Inicio</a>
          <a href="#como-funciona" onClick={() => setMenuOpen(false)}>Cómo funciona</a>
          <a href="#demostracion" onClick={() => setMenuOpen(false)}>Demostración</a>
          <a href="#privacidad" onClick={() => setMenuOpen(false)}>Privacidad</a>
        </nav>
        <a className="nav-cta" href="#demostracion">Explorar <ArrowUpRight size={16} /></a>
        <button ref={menuButton} className="menu-toggle" aria-label={menuOpen ? 'Cerrar menú' : 'Abrir menú'} aria-expanded={menuOpen} onClick={() => setMenuOpen(!menuOpen)}>
          {menuOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </header>

      <main>
        <section className="hero" id="inicio" aria-labelledby="hero-title">
          <div className="hero-grid" aria-hidden="true" />
          <div className="hero-copy">
            <div className="eyebrow"><span className="status-dot" /> TU PRIVACIDAD, MÁS CLARA <span className="eyebrow-line" /></div>
            <h1 id="hero-title">Lo que compartes<br /><em>también cuenta.</em></h1>
            <p className="hero-description">Tus archivos pueden decir más de lo que imaginas. Descubre la información que llevan consigo y comparte con mayor tranquilidad.</p>
            <div className="hero-actions">
              <a className="button button-primary" href="#demostracion">Explorar la experiencia <span><ArrowUpRight size={17} /></span></a>
              <a className="button-text" href="#como-funciona"><span className="play-symbol">↘</span> Cómo funciona</a>
            </div>
            <div className="hero-note"><LockKeyhole size={14} /> Diseño de demostración. Sin procesamiento real.</div>
          </div>
          <div className="hero-visual">
            <div className="visual-glow" />
            <div className="visual-caption"><span>UN ESPACIO PARA TU PRIVACIDAD</span><span>FIG. 01 — METAGUARD</span></div>
            <Suspense fallback={<div className="scene" aria-hidden="true" />}><Scene /></Suspense>
            <div className="orbit-label orbit-label-top"><span className="orbit-icon"><MapPin size={15} /></span><span><small>METADATO</small> Ubicación</span><ArrowUpRight size={13} /></div>
            <div className="orbit-label orbit-label-bottom"><span className="orbit-icon"><Fingerprint size={15} /></span><span><small>METADATO</small> Identidad</span><ArrowUpRight size={13} /></div>
            <div className="visual-bottom"><span>UNA NUEVA PERSPECTIVA</span><span>✳</span></div>
          </div>
          <a className="hero-scroll" href="#como-funciona"><span>DESPLAZA PARA DESCUBRIR</span><ArrowDown size={14} /></a>
          <span className="hero-index" aria-hidden="true">01 / 03</span>
        </section>

        <div className="trust-strip" aria-label="Principios de diseño"><span><Shield size={15} /> PRIVACIDAD POR DISEÑO</span><span className="strip-separator">✳</span><span><ScanLine size={15} /> INFORMACIÓN MÁS CLARA</span><span className="strip-separator">✳</span><span><LockKeyhole size={15} /> TÚ TIENES EL CONTROL</span><span className="strip-end">META / GUARD</span></div>

        <section className="intro section-wrap" id="como-funciona">
          <div className="section-heading"><div><span className="section-kicker"><span>✳</span> EL CONTEXTO IMPORTA</span><h2>Pequeños datos.<br /><em>Gran diferencia.</em></h2></div><p>Una foto o un documento puede contener detalles que no se ven a simple vista. MetaGuard está pensado para hacerlos más fáciles de entender.</p></div>
          <div className="steps-grid">{steps.map(({ n, icon: Icon, title, text }) => <article className="step-card" key={n}><div className="step-top"><span className="step-icon"><Icon size={22} strokeWidth={1.5} /></span><span>{n} / 03</span></div><div><h3>{title}</h3><p>{text}</p></div><ArrowUpRight className="step-arrow" size={17} /></article>)}</div>
        </section>

        <section className="demo-section section-wrap" id="demostracion" aria-labelledby="demo-title">
          <div className="demo-intro"><span className="section-kicker"><span>✳</span> UNA MIRADA AL INTERIOR</span><h2 id="demo-title">Entender es el<br /><em>primer paso.</em></h2><p>Un ejemplo visual de cómo podrías explorar los metadatos de un archivo. No corresponde a un archivo real.</p><div className="demo-callout"><CircleHelp size={19} /><span><strong>Vista de ejemplo</strong><br />El análisis y la limpieza aún no están conectados.</span></div><a className="button button-outline" href="#privacidad">Conoce el proyecto <ArrowRight size={16} /></a></div>
          <div className="demo-window"><div className="window-head"><div className="window-title"><span className="window-icon"><Layers3 size={16} /></span><span><strong>Explorador de metadatos</strong><small>Vista de demostración</small></span></div><span className="sample-badge"><span className="status-dot" /> EJEMPLO</span></div>
            <div className="demo-steps" role="group" aria-label="Etapas de la demostración">
              {demoSteps.map(({ id, number, label }) => <button key={id} type="button" className={`demo-step ${demoStep === id ? 'selected' : ''}`} aria-label={`${Number(number)}. ${label} de ejemplo`} aria-pressed={demoStep === id} onClick={() => showDemoStep(id)}><span>{number}</span>{label}</button>)}
            </div>
            <div className="demo-stage" aria-live="polite" tabIndex={-1} ref={demoStage}>
              {demoStep === 'carga' && <>
                <div className="sample-file"><div className="file-icon"><FileImage size={23} strokeWidth={1.5} /></div><div><strong>archivo-de-ejemplo.jpg</strong><small>Datos ficticios · JPG</small></div><span className="file-tag">SOLO VISTA</span></div>
                <div className="stage-copy"><strong>Carga de ejemplo</strong><p>Ningún archivo se ha seleccionado ni enviado. Esta vista utiliza solo un nombre ficticio.</p></div>
                <button className="demo-action" type="button" onClick={() => showDemoStep('analisis')}>Continuar al análisis de ejemplo <ArrowRight size={15} /></button>
              </>}
              {demoStep === 'analisis' && <>
                <div className="stage-illustration"><ScanLine size={24} strokeWidth={1.5} /></div>
                <div className="stage-copy"><strong>Análisis de ejemplo</strong><p>Así podría verse esta etapa. No se ha recibido un archivo ni se está ejecutando ningún análisis.</p></div>
                <button className="demo-action" type="button" onClick={() => showDemoStep('resultado')}>Ver resultado de ejemplo <ArrowRight size={15} /></button>
              </>}
              {demoStep === 'resultado' && <>
                <div className="risk-heading"><div><strong>Información de ejemplo</strong><p>Datos ficticios; no son el resultado de un análisis real.</p></div><span>03 / 03</span></div>
                <div className="risk-tabs" role="group" aria-label="Categorías de riesgo">{(['Alto', 'Medio', 'Bajo'] as Risk[]).map((item) => <button key={item} type="button" className={`risk-tab ${risk === item ? 'selected' : ''}`} aria-pressed={risk === item} onClick={() => setRisk(item)}><span className={`risk-dot ${item.toLowerCase()}`} />Riesgo {item.toLowerCase()}</button>)}</div>
                <div className="risk-list" aria-live="polite">{example[risk].map(({ label, detail, icon: Icon }) => <div className="risk-row" key={label}><span className="row-icon"><Icon size={18} /></span><span><strong>{label}</strong><small>{detail}</small></span><ArrowUpRight size={15} /></div>)}</div>
                <button className="demo-reset" type="button" onClick={() => { setRisk('Alto'); showDemoStep('carga') }}>Reiniciar ejemplo <ArrowRight size={14} /></button>
              </>}
            </div>
            <div className="window-footer"><span><Sparkles size={14} /> Información ilustrativa, no análisis real</span><span>METAGUARD / 01</span></div>
          </div>
        </section>

        <section className="privacy-section section-wrap" id="privacidad"><div className="privacy-card"><div className="privacy-symbol"><ShieldCheck size={29} strokeWidth={1.3} /></div><div><span className="section-kicker"><span>✳</span> HECHO PARA LA CLARIDAD</span><h2>Comparte con más<br /><em>confianza.</em></h2><p>Estamos construyendo una herramienta para ayudarte a entender y reducir la información que compartes. Por ahora, esta es una muestra visual del proyecto.</p><a href="#inicio" className="privacy-link">Volver al inicio <ArrowUpRight size={16} /></a></div><span className="privacy-decoration" aria-hidden="true">✳</span></div></section>
      </main>
      <footer className="footer section-wrap"><a className="brand footer-brand" href="#inicio"><span className="brand-mark"><ShieldCheck size={18} /></span><span>meta<span className="brand-light">guard</span><span className="brand-dot">.</span></span></a><p>Un poco más de privacidad, en cada archivo.</p><span>PROYECTO EN DESARROLLO <Check size={13} /></span><a href="#inicio" aria-label="Volver al inicio"><ChevronDown className="footer-up" size={18} /></a></footer>
    </div>
  )
}

export default App
