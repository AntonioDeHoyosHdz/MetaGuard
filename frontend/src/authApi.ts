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

export interface LoginResult {
  authenticated: boolean
  mfaRequired: boolean
  csrfToken: string
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

export async function register(email: string, password: string, csrfToken: string): Promise<void> {
  await send('/v1/auth/register', {
    method: 'POST',
    csrfToken,
    body: { email, password },
  })
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
  if (!value.authenticated && !mfaRequired) throw new AuthApiError(0)
  return { authenticated: value.authenticated, mfaRequired, csrfToken: csrfFrom(value) }
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

export async function logout(csrfToken: string): Promise<void> {
  await send('/v1/auth/logout', { method: 'POST', csrfToken })
}
