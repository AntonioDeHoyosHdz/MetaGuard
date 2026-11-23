export class AuthApiError extends Error {
  readonly status: number

  constructor(status: number) {
    super(status === 429 ? 'rate_limited' : status === 403 ? 'security_check' : 'auth_unavailable')
    this.name = 'AuthApiError'
    this.status = status
  }
}

export interface AuthStatus {
  authenticated: boolean
  csrfToken: string | null
}

const securityEventKinds = [
  'login_failed', 'mfa_failed', 'upload_type_mismatch', 'rate_limit_exceeded',
  'new_ip_login', 'dangerous_content_detected', 'leaked_password_rejected',
] as const
export type SecurityEventKind = typeof securityEventKinds[number]
export interface SecurityEvent {
  kind: SecurityEventKind
  created_at: string
}

const knownSecurityEvents: ReadonlySet<string> = new Set(securityEventKinds)

export interface LoginResult {
  authenticated: boolean
  mfaRequired: boolean
  emailChallengeRequired?: true
  csrfToken: string
}

export interface AuthenticatorSetup {
  secret: string
  expiresAt: number
}

export interface AuthenticatorRecoverySetup extends AuthenticatorSetup {
  setupToken: string
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null

async function send(
  path: string,
  options: { method?: 'GET' | 'POST'; csrfToken?: string; body?: Record<string, string> } = {},
): Promise<unknown> {
  const headers: Record<string, string> = {}
  if (options.body) headers['Content-Type'] = 'application/json'
  if (options.csrfToken) headers['X-CSRF-Token'] = options.csrfToken

  let response: Response
  try {
    response = await fetch(path, {
      method: options.method ?? 'GET',
      credentials: 'include',
      cache: 'no-store',
      headers,
      ...(options.body ? { body: JSON.stringify(options.body) } : {}),
    })
  } catch {
    throw new AuthApiError(0)
  }

  if (!response.ok) throw new AuthApiError(response.status)
  try {
    return await response.json()
  } catch {
    throw new AuthApiError(0)
  }
}

function csrfFrom(value: unknown): string {
  if (!isRecord(value) || typeof value.csrf_token !== 'string' || value.csrf_token.length === 0) {
    throw new AuthApiError(0)
  }
  return value.csrf_token
}

export async function getAuthStatus(): Promise<AuthStatus> {
  const value = await send('/v1/auth/status')
  if (
    !isRecord(value) ||
    typeof value.authenticated !== 'boolean' ||
    (value.csrf_token !== null && typeof value.csrf_token !== 'string')
  ) {
    throw new AuthApiError(0)
  }
  return { authenticated: value.authenticated, csrfToken: value.csrf_token }
}

export async function getSecurityEvents(csrfToken: string): Promise<SecurityEvent[]> {
  const value = await send('/v1/security/events', { csrfToken })
  if (!isRecord(value) || Object.keys(value).length !== 1 || !Array.isArray(value.events) || value.events.length > 50) {
    throw new AuthApiError(0)
  }
  return value.events.map((event: unknown) => {
    if (
      !isRecord(event) || Object.keys(event).length !== 2 ||
      typeof event.kind !== 'string' || !knownSecurityEvents.has(event.kind) ||
      typeof event.created_at !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(event.created_at) ||
      !Number.isFinite(Date.parse(event.created_at))
    ) throw new AuthApiError(0)
    return { kind: event.kind as SecurityEventKind, created_at: event.created_at }
  })
}

export async function register(email: string, password: string, csrfToken: string): Promise<void> {
  await send('/v1/auth/register', {
    method: 'POST',
    csrfToken,
    body: { email, password },
  })
}

export async function changePassword(
  currentPassword: string,
  newPassword: string,
  csrfToken: string,
): Promise<void> {
  const value = await send('/v1/users/me/password', {
    method: 'POST',
    csrfToken,
    body: { current_password: currentPassword, new_password: newPassword },
  })
  if (!isRecord(value) || value.changed !== true) throw new AuthApiError(0)
}

export async function resendVerification(email: string, password: string, csrfToken: string): Promise<void> {
  const value = await send('/v1/auth/resend-verification', {
    method: 'POST',
    csrfToken,
    body: { email, password },
  })
  if (!isRecord(value) || value.requested !== true) throw new AuthApiError(0)
}

export async function requestPasswordReset(email: string, csrfToken: string): Promise<void> {
  const value = await send('/v1/auth/password-reset/request', {
    method: 'POST', csrfToken, body: { email },
  })
  if (!isRecord(value) || value.requested !== true) throw new AuthApiError(0)
}

export async function confirmPasswordReset(
  email: string, code: string, newPassword: string, mfaCode: string, csrfToken: string,
): Promise<void> {
  const value = await send('/v1/auth/password-reset/confirm', {
    method: 'POST', csrfToken,
    body: { email, code, new_password: newPassword, ...(mfaCode ? { mfa_code: mfaCode } : {}) },
  })
  if (!isRecord(value) || value.changed !== true) throw new AuthApiError(0)
}

export async function verifyEmail(token: string, csrfToken: string): Promise<void> {
  await send('/v1/auth/verify-email', {
    method: 'POST',
    csrfToken,
    body: { token },
  })
}

export async function login(
  email: string,
  password: string,
  csrfToken: string,
): Promise<LoginResult> {
  const value = await send('/v1/auth/login', {
    method: 'POST',
    csrfToken,
    body: { email, password },
  })
  if (!isRecord(value) || typeof value.authenticated !== 'boolean') throw new AuthApiError(0)
  const mfaRequired = value.mfa_required === true
  const emailChallengeRequired = value.email_challenge_required === true
  if (value.authenticated ? mfaRequired || emailChallengeRequired : mfaRequired === emailChallengeRequired) throw new AuthApiError(0)
  return {
    authenticated: value.authenticated, mfaRequired, csrfToken: csrfFrom(value),
    ...(emailChallengeRequired ? { emailChallengeRequired: true } : {}),
  }
}

export async function completeMfaLogin(
  email: string,
  password: string,
  code: string,
  csrfToken: string,
): Promise<LoginResult> {
  const value = await send('/v1/auth/login/mfa', {
    method: 'POST',
    csrfToken,
    body: { email, password, code },
  })
  if (!isRecord(value) || value.authenticated !== true) throw new AuthApiError(0)
  return { authenticated: true, mfaRequired: false, csrfToken: csrfFrom(value) }
}

export async function completeEmailLogin(
  email: string, password: string, code: string, csrfToken: string,
): Promise<LoginResult> {
  const value = await send('/v1/auth/login/email', {
    method: 'POST', csrfToken, body: { email, password, code },
  })
  if (!isRecord(value) || value.authenticated !== true) throw new AuthApiError(0)
  return { authenticated: true, mfaRequired: false, csrfToken: csrfFrom(value) }
}

export async function logout(csrfToken: string): Promise<void> {
  await send('/v1/auth/logout', { method: 'POST', csrfToken })
}

function authenticatorSetupFrom(value: unknown): AuthenticatorSetup {
  if (
    !isRecord(value) ||
    typeof value.secret !== 'string' || !/^[A-Z2-7]{32}$/.test(value.secret) ||
    typeof value.expires_at !== 'number' || !Number.isSafeInteger(value.expires_at) ||
    value.expires_at <= 0 || value.expires_at > 8_640_000_000_000
  ) {
    throw new AuthApiError(0)
  }
  // The seed is added manually; never navigate to a URI supplied by the API.
  return { secret: value.secret, expiresAt: value.expires_at }
}

function recoveryCodesFrom(value: unknown): string[] {
  if (
    !isRecord(value) || !Array.isArray(value.recovery_codes) || value.recovery_codes.length !== 8 ||
    !value.recovery_codes.every((code: unknown) => typeof code === 'string' && /^[0-9a-f]{32}$/.test(code)) ||
    new Set(value.recovery_codes).size !== 8
  ) {
    throw new AuthApiError(0)
  }
  return [...value.recovery_codes]
}

export async function beginAuthenticatorSetup(password: string, csrfToken: string): Promise<AuthenticatorSetup> {
  return authenticatorSetupFrom(await send('/v1/users/me/totp/setup', {
    method: 'POST', csrfToken, body: { password },
  }))
}

export async function confirmAuthenticatorSetup(code: string, csrfToken: string): Promise<string[]> {
  return recoveryCodesFrom(await send('/v1/users/me/totp/confirm', {
    method: 'POST', csrfToken, body: { code },
  }))
}

export async function beginAuthenticatorRecovery(
  email: string,
  password: string,
  recoveryCode: string,
  csrfToken: string,
): Promise<AuthenticatorRecoverySetup> {
  const value = await send('/v1/auth/mfa/recovery/setup', {
    method: 'POST', csrfToken, body: { email, password, recovery_code: recoveryCode },
  })
  if (
    !isRecord(value) || typeof value.setup_token !== 'string' ||
    value.setup_token.length > 4096 || !/^[A-Za-z0-9_-]+={0,2}$/.test(value.setup_token)
  ) {
    throw new AuthApiError(0)
  }
  return { ...authenticatorSetupFrom(value), setupToken: value.setup_token }
}

export async function confirmAuthenticatorRecovery(
  email: string,
  password: string,
  recoveryCode: string,
  setupToken: string,
  code: string,
  csrfToken: string,
): Promise<string[]> {
  return recoveryCodesFrom(await send('/v1/auth/mfa/recovery/confirm', {
    method: 'POST', csrfToken,
    body: { email, password, recovery_code: recoveryCode, setup_token: setupToken, code },
  }))
}
