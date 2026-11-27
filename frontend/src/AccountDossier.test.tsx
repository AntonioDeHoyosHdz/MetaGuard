import { afterEach, expect, it } from 'vitest'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import AccountDossier from './AccountDossier'

afterEach(cleanup)

it('rotates and resets the cube independently of the form and account stage', () => {
  const login = <label>Correo de acceso<input /></label>
  const { container, rerender } = render(
    <AccountDossier face="login" stage="login">{login}</AccountDossier>,
  )
  const controls = within(screen.getByRole('group', { name: 'Orientación del cubo' }))
  const cube = container.querySelector<HTMLElement>('.access-cube')!
  const input = screen.getByLabelText('Correo de acceso') as HTMLInputElement
  const yaw = () => cube.style.getPropertyValue('--orbit-y')
  const currentStage = () => screen.getAllByRole('listitem')
    .find(item => item.getAttribute('aria-current') === 'step')?.textContent

  fireEvent.change(input, { target: { value: 'example' } })
  fireEvent.click(controls.getByRole('button', { name: 'Girar el cubo' }))
  expect(yaw()).toBe('45deg')
  fireEvent.click(controls.getByRole('button', { name: 'Inclinar el cubo' }))
  expect(cube.style.getPropertyValue('--orbit-x')).toBe('30deg')
  expect(yaw()).toBe('45deg')
  expect(currentStage()).toContain('Acceso')
  expect(screen.getByLabelText('Correo de acceso')).toBe(input)
  expect(input.value).toBe('example')

  fireEvent.click(controls.getByRole('button', { name: 'Restablecer orientación del cubo' }))
  expect(yaw()).toBe('0deg')

  fireEvent.click(controls.getByRole('button', { name: 'Girar el cubo' }))
  rerender(<AccountDossier face="register" stage="register"><p>Formulario de registro</p></AccountDossier>)
  expect(cube.getAttribute('data-face')).toBe('register')
  expect(yaw()).toBe('0deg')
  expect(currentStage()).toContain('Registro')
})

it('follows a mouse drag on both axes and preserves vertical touch gestures', () => {
  const { container } = render(<AccountDossier face="login" stage="login"><p>Formulario</p></AccountDossier>)
  const cube = container.querySelector<HTMLElement>('.access-cube')!
  const orbit = container.querySelector<HTMLElement>('.access-orbit')!
  const reset = screen.getByRole('button', { name: 'Restablecer orientación del cubo' })
  const pitch = () => cube.style.getPropertyValue('--orbit-x')
  const yaw = () => cube.style.getPropertyValue('--orbit-y')

  fireEvent.pointerDown(orbit, { pointerId: 1, isPrimary: true, button: 0, pointerType: 'mouse', clientX: 20, clientY: 30 })
  fireEvent.pointerMove(orbit, { pointerId: 1, clientX: 60, clientY: 50 })
  expect(pitch()).toBe('-12deg')
  expect(yaw()).toBe('24deg')
  fireEvent.pointerUp(orbit, { pointerId: 1 })
  fireEvent.pointerMove(orbit, { pointerId: 1, clientX: 80, clientY: 60 })
  expect(yaw()).toBe('24deg')
  fireEvent.click(reset)

  fireEvent.pointerDown(orbit, { pointerId: 2, isPrimary: true, button: 0, pointerType: 'touch', clientX: 20, clientY: 30 })
  fireEvent.pointerMove(orbit, { pointerId: 2, clientX: 24, clientY: 50 })
  expect(yaw()).toBe('0deg')
  fireEvent.pointerCancel(orbit, { pointerId: 2 })
  fireEvent.pointerDown(orbit, { pointerId: 3, isPrimary: true, button: 0, pointerType: 'touch', clientX: 20, clientY: 30 })
  fireEvent.pointerMove(orbit, { pointerId: 3, clientX: 60, clientY: 36 })
  expect(pitch()).toBe('0deg')
  expect(yaw()).toBe('24deg')
  fireEvent.lostPointerCapture(orbit, { pointerId: 3 })
  fireEvent.pointerMove(orbit, { pointerId: 3, clientX: 90, clientY: 42 })
  expect(yaw()).toBe('24deg')
})
