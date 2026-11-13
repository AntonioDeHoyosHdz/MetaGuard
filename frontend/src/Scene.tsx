import { useEffect, useRef, useState } from 'react'
import * as THREE from 'three'

function Fallback() {
  return <svg className="scene-fallback" viewBox="0 0 420 420" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="glass" x1="60" y1="50" x2="350" y2="340" gradientUnits="userSpaceOnUse"><stop stopColor="#A5FFF0" stopOpacity=".28" /><stop offset="1" stopColor="#40D7C6" stopOpacity=".04" /></linearGradient></defs><ellipse cx="210" cy="344" rx="150" ry="25" stroke="#50E3D0" strokeOpacity=".16" /><path d="M94 124 211 60l116 64v140l-116 67-117-67V124Z" fill="url(#glass)" stroke="#145F62" strokeOpacity=".72" /><path d="m94 124 117 67 116-67M211 191v140" stroke="#145F62" strokeOpacity=".48" /><rect x="169" y="135" width="83" height="109" rx="9" fill="#A4FFF0" fillOpacity=".14" stroke="#174C51" strokeOpacity=".72" /><path d="M185 161h49M185 176h39M185 191h48M185 206h29" stroke="#184E53" strokeOpacity=".6" strokeWidth="3" strokeLinecap="round" /></svg>
}

export default function Scene() {
  const container = useRef<HTMLDivElement>(null)
  const [fallback, setFallback] = useState(false)

  useEffect(() => {
    const host = container.current
    if (!host) return
    let renderer: THREE.WebGLRenderer
    try {
      renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: 'low-power' })
    } catch {
      setFallback(true)
      return
    }
    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(32, 1, 0.1, 100)
    camera.position.set(4.8, 3.2, 6.8)
    camera.lookAt(0, 0, 0)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5))
    renderer.setClearColor(0x000000, 0)
    host.appendChild(renderer.domElement)

    scene.add(new THREE.AmbientLight(0xc8fff8, 1.5))
    const key = new THREE.PointLight(0x87fff0, 45, 20)
    key.position.set(4, 5, 5)
    scene.add(key)
    const light = new THREE.PointLight(0x267f90, 25, 15)
    light.position.set(-4, -1, -2)
    scene.add(light)

    const group = new THREE.Group()
    scene.add(group)
    const ring = new THREE.Mesh(
      new THREE.TorusGeometry(2.05, 0.018, 8, 100),
      new THREE.MeshBasicMaterial({ color: 0x1b6f79, transparent: true, opacity: 0.52 }),
    )
    ring.rotation.x = Math.PI / 2.7
    ring.rotation.y = -0.35
    group.add(ring)
    const boxGeometry = new THREE.BoxGeometry(2.45, 2.45, 2.45)
    const glass = new THREE.MeshPhysicalMaterial({ color: 0x57e7d7, metalness: 0.08, roughness: 0.16, transparent: true, opacity: 0.10, side: THREE.DoubleSide, depthWrite: false })
    group.add(new THREE.Mesh(boxGeometry, glass))
    const edges = new THREE.LineSegments(new THREE.EdgesGeometry(boxGeometry), new THREE.LineBasicMaterial({ color: 0x167d83, transparent: true, opacity: 0.85 }))
    group.add(edges)
    const inner = new THREE.Mesh(new THREE.BoxGeometry(1.7, 1.7, 1.7), new THREE.MeshBasicMaterial({ color: 0x82ffee, transparent: true, opacity: 0.035, side: THREE.BackSide, depthWrite: false }))
    group.add(inner)

    const file = new THREE.Group()
    const card = new THREE.Mesh(new THREE.BoxGeometry(0.95, 1.32, 0.06), new THREE.MeshPhysicalMaterial({ color: 0xb7fff3, transparent: true, opacity: 0.72, metalness: 0.15, roughness: 0.2 }))
    file.add(card)
    for (let index = 0; index < 4; index += 1) {
      const line = new THREE.Mesh(new THREE.BoxGeometry(index === 3 ? 0.38 : 0.58, 0.025, 0.015), new THREE.MeshBasicMaterial({ color: 0x126e70 }))
      line.position.set(index === 3 ? -0.1 : 0, 0.22 - index * 0.15, 0.04)
      file.add(line)
    }
    file.rotation.y = -0.12
    group.add(file)

    const motion = window.matchMedia('(prefers-reduced-motion: reduce)')
    let frame = 0
    let stopped = false
    let motionStart: number | null = null
    const render = (time = performance.now()) => {
      if (stopped) return
      if (!motion.matches) {
        motionStart ??= time
        group.rotation.y = Math.sin(time / 2800) * 0.16
        group.rotation.x = Math.sin(time / 4000) * 0.045
      } else {
        group.rotation.set(0, 0, 0)
      }
      renderer.render(scene, camera)
      // Stop automatically before five seconds; no persistent decorative motion.
      if (!motion.matches && motionStart !== null && time - motionStart < 4000) frame = window.requestAnimationFrame(render)
    }
    const resize = () => {
      if (stopped) return
      const width = Math.max(host.clientWidth, 1)
      const height = Math.max(host.clientHeight, 1)
      camera.aspect = width / height
      camera.updateProjectionMatrix()
      renderer.setSize(width, height, false)
      if (motion.matches) render()
      else if (motionStart !== null && performance.now() - motionStart >= 4000) renderer.render(scene, camera)
    }
    const handleMotion = () => {
      window.cancelAnimationFrame(frame)
      motionStart = null
      render()
    }
    const handleContextLost = () => {
      stopped = true
      window.cancelAnimationFrame(frame)
      renderer.domElement.remove()
      setFallback(true)
    }
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(resize)
    if (observer) observer.observe(host)
    else window.addEventListener('resize', resize)
    motion.addEventListener('change', handleMotion)
    renderer.domElement.addEventListener('webglcontextlost', handleContextLost)
    resize()
    if (!motion.matches) render()

    return () => {
      stopped = true
      window.cancelAnimationFrame(frame)
      observer?.disconnect()
      window.removeEventListener('resize', resize)
      motion.removeEventListener('change', handleMotion)
      renderer.domElement.removeEventListener('webglcontextlost', handleContextLost)
      scene.traverse((object) => {
        if (object instanceof THREE.Mesh || object instanceof THREE.LineSegments) {
          object.geometry.dispose()
          const materials = Array.isArray(object.material) ? object.material : [object.material]
          materials.forEach((material) => material.dispose())
        }
      })
      renderer.dispose()
      renderer.domElement.remove()
    }
  }, [])

  return <div className="scene" ref={container} aria-hidden="true">{fallback && <Fallback />}</div>
}
