import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  AuthApiError,
  beginAuthenticatorRecovery,
  beginAuthenticatorSetup,
  changePassword,
  completeMfaLogin,
  completeEmailLogin,
  confirmPasswordReset,
  confirmAuthenticatorRecovery,
  confirmAuthenticatorSetup,
  getAuthStatus,
  getSecurityEvents,
  login,
  logout,
  register,
  resendVerification,
  requestPasswordReset,
  verifyEmail,
} from './authApi'

afterEach(() => vi.unstubAllGlobals())

describe('auth API client', () => {
  it('requests private activity with CSRF and rejects extra owner data', async () => {
    const event = { kind: 'login_failed', created_at: '2026-11-21T12:00:00Z' }
    const request = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ events: [event] }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ events: [{ ...event, owner_id: 'private' }] }) })
    vi.stubGlobal('fetch', request)
    await expect(getSecurityEvents('csrf')).resolves.toEqual([event])
    expect(request).toHaveBeenNthCalledWith(1, '/v1/security/events', {
      method: 'GET', credentials: 'include', cache: 'no-store', headers: { 'X-CSRF-Token': 'csrf' },
    })
    await expect(getSecurityEvents('csrf')).rejects.toBeInstanceOf(AuthApiError)
  })

  it('recognizes a separate email sign-in proof and sends it only in the request body', async () => {
    const request = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ authenticated: false, email_challenge_required: true, csrf_token: 'mail-csrf' }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ authenticated: true, csrf_token: 'session-csrf' }) })
    vi.stubGlobal('fetch', request)
    const email = 'synthetic@example.test'
    const code = 'a'.repeat(32)
    expect(await login(email, 'synthetic password', 'preauth')).toEqual({ authenticated: false, mfaRequired: false, emailChallengeRequired: true, csrfToken: 'mail-csrf' })
    expect(await completeEmailLogin(email, 'synthetic password', code, 'mail-csrf')).toEqual({ authenticated: true, mfaRequired: false, csrfToken: 'session-csrf' })
    expect(request).toHaveBeenNthCalledWith(2, '/v1/auth/login/email', {
      method: 'POST', credentials: 'include', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'mail-csrf' },
      body: JSON.stringify({ email, password: 'synthetic password', code }),
    })
  })

  it('changes a signed-in password with a same-origin, no-store POST', async () => {
    const request = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ changed: true }) })
    vi.stubGlobal('fetch', request)
    await expect(changePassword('synthetic current', 'synthetic next', 'csrf')).resolves.toBeUndefined()
    expect(request).toHaveBeenCalledExactlyOnceWith('/v1/users/me/password', {
      method: 'POST', credentials: 'include', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'csrf' },
      body: JSON.stringify({ current_password: 'synthetic current', new_password: 'synthetic next' }),
    })
  })

  it('requests a new verification code with credentials in a no-store POST only', async () => {
    const request = vi.fn().mockResolvedValue({ ok: true, status: 202, json: async () => ({ requested: true }) })
    vi.stubGlobal('fetch', request)
    await expect(resendVerification('pending@example.test', 'synthetic only', 'csrf')).resolves.toBeUndefined()
    expect(request).toHaveBeenCalledExactlyOnceWith('/v1/auth/resend-verification', {
      method: 'POST', cache: 'no-store', credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'csrf' },
      body: JSON.stringify({ email: 'pending@example.test', password: 'synthetic only' }),
    })
  })

  it('sends recovery credentials only in same-origin no-store POST bodies', async () => {
    const request = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ requested: true }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ changed: true }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ changed: true }) })
    vi.stubGlobal('fetch', request)
    const email = 'demo@example.test'
    const code = 'abcdef0123456789'.repeat(2)
    const password = 'synthetic next password'
    await requestPasswordReset(email, 'csrf')
    await confirmPasswordReset(email, code, password, '123456', 'csrf')
    await confirmPasswordReset(email, code, password, '', 'csrf')
    const post = (body: Record<string, string>) => ({
      method: 'POST', cache: 'no-store', credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'csrf' },
      body: JSON.stringify(body),
    })
    expect(request.mock.calls).toEqual([
      ['/v1/auth/password-reset/request', post({ email })],
      ['/v1/auth/password-reset/confirm', post({ email, code, new_password: password, mfa_code: '123456' })],
      ['/v1/auth/password-reset/confirm', post({ email, code, new_password: password })],
    ])
  })

  it('sends all authenticator setup and recovery proofs only in same-origin no-store POSTs', async () => {
    const backupCode = 'a'.repeat(32)
    const codes = Array.from({ length: 8 }, (_, index) => index.toString(16).padStart(32, '0'))
    const seed = {
      secret: 'A'.repeat(32), expires_at: 4_102_444_800,
      otpauth_uri: 'https://example.test/should-not-be-used',
    }
    const ok = (value: unknown) => ({ ok: true, status: 200, json: async () => value })
    const request = vi.fn()
      .mockResolvedValueOnce(ok(seed))
      .mockResolvedValueOnce(ok({ recovery_codes: codes }))
      .mockResolvedValueOnce(ok({ ...seed, setup_token: 'local-recovery-proof' }))
      .mockResolvedValueOnce(ok({ recovery_codes: codes }))
    vi.stubGlobal('fetch', request)

    await expect(beginAuthenticatorSetup('password', 'session-csrf'))
      .resolves.toEqual({ secret: seed.secret, expiresAt: seed.expires_at })
    await expect(confirmAuthenticatorSetup('123456', 'session-csrf')).resolves.toEqual(codes)
    await expect(beginAuthenticatorRecovery('demo@example.test', 'password', backupCode, 'challenge-csrf'))
      .resolves.toEqual({ secret: seed.secret, expiresAt: seed.expires_at, setupToken: 'local-recovery-proof' })
    await expect(confirmAuthenticatorRecovery(
      'demo@example.test', 'password', backupCode, 'local-recovery-proof', '123456', 'challenge-csrf',
    )).resolves.toEqual(codes)
    expect(request.mock.calls.map(([path, options]) => [path, JSON.parse(options.body)])).toEqual([
      ['/v1/users/me/totp/setup', { password: 'password' }],
      ['/v1/users/me/totp/confirm', { code: '123456' }],
      ['/v1/auth/mfa/recovery/setup', { email: 'demo@example.test', password: 'password', recovery_code: backupCode }],
      ['/v1/auth/mfa/recovery/confirm', { email: 'demo@example.test', password: 'password', recovery_code: backupCode, setup_token: 'local-recovery-proof', code: '123456' }],
    ])
    for (const [index, [, options]] of request.mock.calls.entries()) {
      expect(options).toMatchObject({
        method: 'POST', credentials: 'include', cache: 'no-store',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': index < 2 ? 'session-csrf' : 'challenge-csrf' },
      })
      expect(options.headers).not.toHaveProperty('Origin')
    }
  })

  it('rejects malformed setup proof and recovery-code batches without copying server data to errors', async () => {
    const request = vi.fn()
      .mockResolvedValueOnce({
        ok: true, status: 200,
        json: async () => ({ secret: 'untrusted-seed', expires_at: 1_800_000_000 }),
      })
      .mockResolvedValueOnce({
        ok: true, status: 200, json: async () => ({ recovery_codes: Array(8).fill('c'.repeat(32)) }),
      })
    vi.stubGlobal('fetch', request)
    await expect(beginAuthenticatorSetup('password', 'csrf')).rejects.toMatchObject({ status: 0 })
    await expect(confirmAuthenticatorSetup('123456', 'csrf')).rejects.toMatchObject({ status: 0 })
  })

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
