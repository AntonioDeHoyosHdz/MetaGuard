import { cleanup, fireEvent, render, act } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import Scene from './Scene'

it('scrolls through the atlas on desktop/mobile, obeys live motion preferences and cancels work on unmount', () => {
  let reduced = false
  let mobile = false
  let top = 0
  let ownTop = 400
  const requests = new Map<number, FrameRequestCallback>()
  let id = 0
  const media = new EventTarget()
  const motion = {
    get matches() { return reduced },
    addEventListener: media.addEventListener.bind(media),
    removeEventListener: media.removeEventListener.bind(media),
  }
  vi.stubGlobal('matchMedia', (query: string) => query.includes('reduced') ? motion : { get matches() { return mobile } })
  vi.stubGlobal('innerHeight', 1000)
  vi.stubGlobal('requestAnimationFrame', (fn: FrameRequestCallback) => { requests.set(++id, fn); return id })
  vi.stubGlobal('cancelAnimationFrame', (id: number) => requests.delete(id))
  const removed = vi.spyOn(motion, 'removeEventListener')
  const bounds = (top: number, height: number) => ({ top, height }) as DOMRect
  vi.spyOn(Element.prototype, 'getBoundingClientRect').mockImplementation(function(this: Element) {
    return this.classList.contains('scene') ? bounds(ownTop, 400) : bounds(top, 2200)
  })
  const tick = () => act(() => {
    for (const [id, fn] of Array.from(requests)) { requests.delete(id); fn(0) }
  })
  try {
    const { container, unmount } = render(<div className="hero"><Scene /></div>)
    const img = () => container.querySelector('img')!
    const visual = () => img().style.transform
    expect(img().getAttribute('src')).toMatch(/privacy-vault-sequence\.png$/)
    expect(img().closest('.scene')?.getAttribute('aria-hidden')).toBe('true')
    tick()
    expect(visual()).toBe('translate(0%, 0%)')
    top = -300
    fireEvent.scroll(window)
    fireEvent.scroll(window)
    expect(requests.size).toBe(1)
    tick()
    expect(visual()).toBe('translate(0%, -25%)')
    top = -1200
    fireEvent.scroll(window)
    tick()
    expect(visual()).toBe('translate(-80%, -75%)')
    reduced = true
    media.dispatchEvent(new Event('change'))
    tick()
    expect(visual()).toBe('translate(0%, 0%)')
    reduced = false
    mobile = true
    ownTop = 0
    fireEvent.resize(window)
    tick()
    expect(visual()).toBe('translate(0%, -50%)')
    ownTop = -390
    fireEvent.scroll(window)
    tick()
    expect(visual()).toBe('translate(-80%, -75%)')
    fireEvent.error(img())
    expect(container.querySelector('.scene-fallback')).toBeTruthy()
    fireEvent.scroll(window)
    expect(requests.size).toBe(1)
    unmount()
    expect(requests.size).toBe(0)
    expect(removed).toHaveBeenCalledWith('change', expect.any(Function))
    fireEvent.scroll(window)
    fireEvent.resize(window)
    expect(requests.size).toBe(0)
  } finally {
    cleanup()
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  }
})
