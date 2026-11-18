import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  AuthApiError,
  completeMfaLogin,
  getAuthStatus,
  login,
  logout,
  register,
  verifyEmail,
} from './authApi'

afterEach(() => vi.unstubAllGlobals())

describe('auth API client', () => {
  it('loads only the minimal authenticated status and keeps cookies included', async () => {
    const request = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ authenticated: false, csrf_token: 'csrf-memory-only', session_token: 'ignore-me' }),
    })
    vi.stubGlobal('fetch', request)

    await expect(getAuthStatus()).resolves.toEqual({ authenticated: false, csrfToken: 'csrf-memory-only' })
    expect(request).toHaveBeenCalledWith('/v1/auth/status', expect.objectContaining({ credentials: 'include', cache: 'no-store' }))
  })

  it('sends the in-memory CSRF token on each auth mutation without setting Origin', async () => {
    const request = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ authenticated: true, csrf_token: 'next-csrf' }) })
    vi.stubGlobal('fetch', request)

    await register('a@example.test', 'a long synthetic password', 'csrf-1')
    await verifyEmail('verification-token', 'csrf-2')
    await login('a@example.test', 'password', 'csrf-3')
    await completeMfaLogin('a@example.test', 'password', '123456', 'csrf-4')
    await logout('csrf-5')

    expect(request).toHaveBeenCalledTimes(5)
    for (const [url, options] of request.mock.calls) {
      expect(url).toMatch(/^\/v1\/auth\//)
      expect(options.credentials).toBe('include')
      expect(options.headers['X-CSRF-Token']).toMatch(/^csrf-/)
      expect(options.headers).not.toHaveProperty('Origin')
    }
    expect(request.mock.calls.map(([url]) => url)).toEqual([
      '/v1/auth/register',
      '/v1/auth/verify-email',
      '/v1/auth/login',
      '/v1/auth/login/mfa',
      '/v1/auth/logout',
    ])
  })

  it('returns only the documented login state and CSRF token, never token-like fields', async () => {
    const request = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ authenticated: false, mfa_required: true, csrf_token: 'csrf-next', jwt: 'must-not-escape' }),
    })
    vi.stubGlobal('fetch', request)

    await expect(login('a@example.test', 'password', 'csrf')).resolves.toEqual({ authenticated: false, mfaRequired: true, csrfToken: 'csrf-next' })
  })

  it('exposes status-only errors for rate limits instead of server text', async () => {
    const request = vi.fn().mockResolvedValue({ ok: false, status: 429, json: async () => ({ error: { message: 'private token text' } }) })
    vi.stubGlobal('fetch', request)

    await expect(getAuthStatus()).rejects.toMatchObject({ name: 'AuthApiError', status: 429 })
    try {
      await getAuthStatus()
    } catch (error) {
      expect(error).toBeInstanceOf(AuthApiError)
      expect(String(error)).not.toContain('private token text')
    }
  })
})
