import { afterEach, expect, it } from 'vitest'
import { cleanup, fireEvent, render } from '@testing-library/react'
import Scene, { frameForProgress, scrollProgress, visibleProgress } from './Scene'

afterEach(cleanup)

it('maps scroll progress to the twenty frames without exceeding the sheet', () => {
  expect(frameForProgress(-1, false)).toBe(0)
  expect(frameForProgress(0.5, false)).toBe(10)
  expect(frameForProgress(2, false)).toBe(19)
  expect(scrollProgress(-500, 2000, 1000)).toBe(0.5)
  expect(visibleProgress(700, 350, 844)).toBe(0)
  expect(visibleProgress(100, 350, 844)).toBeGreaterThan(0)
  expect(visibleProgress(-350, 350, 844)).toBe(1)
})

it('keeps a static frame when reduced motion is requested', () => {
  expect(frameForProgress(0.9, true)).toBe(0)
})

it('shows a local fallback if the image cannot load', () => {
  const { container } = render(<div className="hero"><Scene /></div>)
  const image = container.querySelector('img')
  expect(image).not.toBeNull()
  fireEvent.error(image!)
  expect(container.querySelector('svg.scene-fallback')).not.toBeNull()
})
