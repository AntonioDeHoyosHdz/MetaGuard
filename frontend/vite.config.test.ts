import { inspect } from 'node:util'
import { describe, expect, it, vi } from 'vitest'
import { createConfig, localReadOrigin } from './vite.config'

describe('the development API proxy', () => {
  it('forwards liveness, readiness, and versioned API routes only', () => {
    const config = createConfig({ command: 'serve' }, {})
    const proxy = config.server?.proxy ?? {}
    const targetFor = (path: string) => {
      const rule = Object.entries(proxy).find(([pattern]) => new RegExp(pattern).test(path))?.[1]
      return typeof rule === 'string' ? rule : rule?.target
    }

    expect(targetFor('/health/live')).toBe('http://127.0.0.1:8000')
    expect(targetFor('/health/ready')).toBe('http://127.0.0.1:8000')
    expect(targetFor('/health/ready?check=1')).toBe('http://127.0.0.1:8000')
    expect(targetFor('/v1/auth/status')).toBe('http://127.0.0.1:8000')
    expect(targetFor('/health/readyness')).toBeUndefined()
    expect(targetFor('/health/ready/extra')).toBeUndefined()
    expect(targetFor('/v10/auth/status')).toBeUndefined()
    expect(config.preview?.proxy).toEqual({})
  })

  it('supplies the exact local HTTPS origin only for same-origin protected browser reads', () => {
    const headers = {
      host: '127.0.0.1:5173',
      referer: 'https://127.0.0.1:5173/',
      'sec-fetch-site': 'same-origin',
      'x-csrf-token': 'synthetic',
    }
    const request = { method: 'GET', url: '/v1/reports', headers }
    for (const url of ['/v1/reports', '/v1/reports/demo', '/v1/security/events']) {
      expect(localReadOrigin({ ...request, url }, true)).toBe('https://127.0.0.1:5173')
    }
    expect(localReadOrigin(request, false)).toBeUndefined()
    expect(localReadOrigin({ ...request, url: '/v1/downloads/demo' }, true)).toBeUndefined()
    expect(localReadOrigin({ ...request, method: 'POST', url: '/v1/downloads' }, true)).toBeUndefined()
    expect(localReadOrigin({ ...request, method: 'DELETE' }, true)).toBeUndefined()
    expect(localReadOrigin({ ...request, url: '/v1/auth/status' }, true)).toBeUndefined()
    expect(localReadOrigin({ ...request, url: '/v1/security/events/other' }, true)).toBeUndefined()
    expect(localReadOrigin({ ...request, url: '/v1/security/events', method: 'POST' }, true)).toBeUndefined()
    expect(localReadOrigin({ ...request, headers: { ...headers, origin: 'null' } }, true)).toBeUndefined()
    expect(localReadOrigin({ ...request, headers: { ...headers, 'sec-fetch-site': 'cross-site' } }, true)).toBeUndefined()
    expect(localReadOrigin({ ...request, headers: { ...headers, referer: 'https://127.0.0.1:5174/' } }, true)).toBeUndefined()
    expect(localReadOrigin({ ...request, headers: { ...headers, 'x-csrf-token': undefined } }, true)).toBeUndefined()
  })

  it('recognizes the loopback authority on protected HTTP/2 reads without accepting ambiguity', () => {
    const headers = {
      ':authority': '127.0.0.1:5175',
      referer: 'https://127.0.0.1:5175/',
      'sec-fetch-site': 'same-origin',
      'x-csrf-token': 'synthetic',
    }
    const request = { method: 'GET', url: '/v1/reports', headers }
    expect(localReadOrigin(request, true)).toBe('https://127.0.0.1:5175')
    expect(localReadOrigin(request, false)).toBeUndefined()
    expect(localReadOrigin({ ...request, headers: { ...headers, host: 'localhost:5175' } }, true)).toBeUndefined()
    expect(localReadOrigin({ ...request, headers: { ...headers, referer: 'https://localhost:5175/' } }, true)).toBeUndefined()
    expect(localReadOrigin({ ...request, headers: { ...headers, ':authority': undefined } }, true)).toBeUndefined()
  })

  it('configures HTTPS only for development serving with an explicitly supplied pair', () => {
    const env = {
      METAGUARD_DEV_TLS_CERT: 'local-cert.pem',
      METAGUARD_DEV_TLS_KEY: 'local-key.pem',
    }
    const readPem = vi.fn((path: string) => Buffer.from(path))
    expect(createConfig({ command: 'build' }, env, readPem).server?.https).toBeUndefined()
    expect(createConfig({ command: 'serve', mode: 'test' }, env, readPem).server?.https).toBeUndefined()
    const preview = createConfig({ command: 'serve', isPreview: true }, env, readPem)
    expect(preview.server?.https).toBeUndefined()
    expect(preview.preview?.proxy).toEqual({})
    expect(readPem).not.toHaveBeenCalled()
    expect(createConfig({ command: 'serve' }, {}, readPem).server?.https).toBeUndefined()
    const https = createConfig({ command: 'serve' }, env, readPem).server?.https
    expect(Buffer.from(https?.cert as Buffer).toString()).toBe('local-cert.pem')
    expect(Buffer.from(https?.key as Buffer).toString()).toBe('local-key.pem')
    expect(inspect(https)).not.toContain('local-key.pem')
    expect(JSON.stringify(https)).not.toContain('local-key.pem')
    expect(readPem.mock.calls).toEqual([['local-cert.pem'], ['local-key.pem']])
  })

  it('fails closed without exposing paths when the PEM pair is incomplete or unreadable', () => {
    const readPem = vi.fn(() => { throw new Error('read failure with private path') })
    expect(() => createConfig({ command: 'serve' }, { METAGUARD_DEV_TLS_KEY: 'private-key.pem' }, readPem))
      .toThrow(/^Set both METAGUARD_DEV_TLS_CERT and METAGUARD_DEV_TLS_KEY to use local HTTPS\.$/)
    expect(() => createConfig({ command: 'serve' }, {
      METAGUARD_DEV_TLS_CERT: 'cert.pem',
      METAGUARD_DEV_TLS_KEY: 'private-key.txt',
    }, readPem)).toThrow(/^Local HTTPS requires PEM files with a \.pem extension\.$/)
    expect(readPem).not.toHaveBeenCalled()
    expect(() => createConfig({ command: 'serve' }, {
      METAGUARD_DEV_TLS_CERT: 'local cert.pem',
      METAGUARD_DEV_TLS_KEY: 'private key.pem',
    }, readPem)).toThrow(/^Unable to read the local HTTPS certificate or key\.$/)
  })
})
