import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, render } from '@testing-library/react'
import Scene from './Scene'

vi.mock('three', () => ({
  WebGLRenderer: class { constructor() { throw new Error('WebGL unavailable') } },
}))
afterEach(cleanup)

it('shows the local SVG fallback when WebGL cannot start', () => {
  const { container } = render(<Scene />)
  expect(container.querySelector('svg.scene-fallback')).not.toBeNull()
})
