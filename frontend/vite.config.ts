import { defineConfig, type ConfigEnv, type UserConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

const apiTarget = 'http://127.0.0.1:8000'
type LocalEnv = Record<string, string | undefined>
type PemReader = (path: string) => Uint8Array
// Vite runs this config on Node, outside the typed browser bundle.
const nodeRuntime = (globalThis as unknown as {
  process: { env: LocalEnv; getBuiltinModule: (name: 'node:fs') => { readFileSync: PemReader } }
}).process
const readLocalPem: PemReader = (path) => nodeRuntime.getBuiltinModule('node:fs').readFileSync(path)

function redactPem(pem: Uint8Array): Uint8Array {
  // Buffers are still passed intact to TLS; diagnostic inspection does not
  // print their contents when Vite logs its resolved config.
  Object.defineProperties(pem, {
    [Symbol.for('nodejs.util.inspect.custom')]: { value: () => '[local TLS PEM]' },
    toJSON: { value: () => '[local TLS PEM]' },
  })
  return pem
}

type ProtectedRead = {
  method?: string
  url?: string
  headers: Record<string, string | string[] | undefined>
}
type ReadOriginProxy = {
  on(event: 'proxyReq', handler: (
    outgoing: { setHeader(name: string, value: string): void },
    incoming: ProtectedRead & { socket: { encrypted?: boolean } },
  ) => void): void
}

export function localReadOrigin({ method, url, headers }: ProtectedRead, encrypted: boolean) {
  const { host, referer, ':authority': authority } = headers
  // Chromium can negotiate HTTP/2, where the authority can replace Host.
  if (host !== undefined && authority !== undefined && host !== authority) return undefined
  const requestHost = host ?? authority
  const path = url?.split('?', 1)[0] ?? ''
  // Browsers omit Origin on same-origin GETs. Keep the API's strict Origin and
  // CSRF checks and supply Origin only for these authenticated TLS proxy reads.
  if (
    !encrypted || method !== 'GET' || headers.origin !== undefined ||
    !(path === '/v1/security/events' || /^\/v1\/reports(?:\/[^/?]+)?$/.test(path)) ||
    headers['sec-fetch-site'] !== 'same-origin' ||
    typeof headers['x-csrf-token'] !== 'string' || !headers['x-csrf-token'] ||
    typeof requestHost !== 'string' || !/^(127\.0\.0\.1|localhost|\[::1\])(?::[0-9]{1,5})?$/.test(requestHost) ||
    typeof referer !== 'string'
  ) return undefined
  try {
    const origin = new URL(`https://${requestHost}`).origin
    const source = new URL(referer)
    return !source.username && !source.password && source.origin === origin ? origin : undefined
  } catch {
    return undefined
  }
}

export function createConfig(
  { command, isPreview, mode }: Pick<ConfigEnv, 'command' | 'isPreview'> & { mode?: string },
  env: LocalEnv = nodeRuntime.env,
  readPem: PemReader = readLocalPem,
): UserConfig {
  const isDevServer = command === 'serve' && !isPreview && mode !== 'test'
  const certPath = isDevServer ? env.METAGUARD_DEV_TLS_CERT : undefined
  const keyPath = isDevServer ? env.METAGUARD_DEV_TLS_KEY : undefined
  if ((certPath !== undefined || keyPath !== undefined) && (!certPath || !keyPath)) {
    throw new Error('Set both METAGUARD_DEV_TLS_CERT and METAGUARD_DEV_TLS_KEY to use local HTTPS.')
  }
  if (certPath && keyPath && ![certPath, keyPath].every((path) => /\.pem$/i.test(path))) {
    throw new Error('Local HTTPS requires PEM files with a .pem extension.')
  }
  let https: NonNullable<UserConfig['server']>['https']
  if (certPath && keyPath) {
    try {
      https = { cert: redactPem(readPem(certPath)), key: redactPem(readPem(keyPath)) }
    } catch {
      throw new Error('Unable to read the local HTTPS certificate or key.')
    }
  }

  return {
    plugins: [react(), tailwindcss()],
    preview: { proxy: {} },
    server: {
      https,
      proxy: {
        '^/health/live(?:\\?|$)': apiTarget,
        '^/health/ready(?:\\?|$)': apiTarget,
        '^/v1(?:/|\\?|$)': https ? {
          target: apiTarget,
          configure(proxy) {
            // The browser-only typecheck omits Node's EventEmitter declarations.
            const events = proxy as typeof proxy & ReadOriginProxy
            events.on('proxyReq', (outgoing, incoming) => {
              const origin = localReadOrigin(incoming, incoming.socket.encrypted === true)
              if (origin !== undefined) outgoing.setHeader('Origin', origin)
            })
          },
        } : apiTarget,
      },
    },
  }
}

export default defineConfig((context) => createConfig(context))
