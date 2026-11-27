import test from 'node:test';
import assert from 'node:assert/strict';
import origin from './origin.mjs';

const base = 'https://127.0.0.1:8443';
const good = [
  ['Host', '127.0.0.1:8443'],
  ['Referer', `${base}/security/events`],
  ['Sec-Fetch-Site', 'same-origin'],
  ['X-CSRF-Token', 'a'.repeat(43)],
];
const request = ({ rawHeadersIn = good, method = 'GET', scheme = 'https', uri = '/v1/reports' } = {}) => ({
  rawHeadersIn, method, variables: { scheme, request_uri: uri },
});

test('supplies Origin only for protected, literal same-origin GETs', () => {
  for (const uri of ['/v1/reports', '/v1/security/events?limit=5', '/v1/reports/123e4567-e89b-12d3-a456-426614174000']) {
    assert.equal(origin.value(request({ uri })), base);
  }
  for (const uri of ['/v1/auth/status', '/v1/reports/another', '/v1/reports/', '/v1/%72eports', '/v1/x/../reports']) {
    assert.equal(origin.value(request({ uri })), '');
  }
  assert.equal(origin.value(request({ method: 'POST' })), '');
  assert.equal(origin.value(request({ scheme: 'http' })), '');
});

test('preserves a supplied Origin and rejects blank or duplicate values', () => {
  const existing = request({ rawHeadersIn: [...good, ['oRiGiN', 'https://other.test']] });
  assert.equal(origin.value(existing), 'https://other.test');
  assert.equal(origin.invalid(existing), '0');
  for (const rawHeadersIn of [[...good, ['Origin', '']], [...good, ['Origin', base], ['origin', base]]]) {
    assert.equal(origin.invalid(request({ rawHeadersIn })), '1');
    assert.equal(origin.value(request({ rawHeadersIn })), '');
  }
});

test('fails closed for missing or ambiguous provenance headers', () => {
  for (const [name] of good) {
    assert.equal(origin.value(request({ rawHeadersIn: good.filter(([key]) => key !== name) })), '');
  }
  for (const [name, value] of [['Host', 'localhost:8443'], ['Referer', `${base}.other.test/`], ['Sec-Fetch-Site', 'cross-site'], ['X-CSRF-Token', 'x']]) {
    assert.equal(origin.value(request({ rawHeadersIn: good.map(([key, val]) => [key, key === name ? value : val]) })), '');
  }
  assert.equal(origin.value(request({ rawHeadersIn: [...good, ['x-csrf-token', 'b'.repeat(43)]] })), '');
  assert.equal(origin.invalid(request({ rawHeadersIn: [...good, ['X-Forwarded-Unrecognized', 'x']] })), '1');
  assert.equal(origin.invalid(request({ rawHeadersIn: [...good, ['Forwarded', 'for=guest']] })), '0');
});

test('only the named HTTPS trial can complete Origin or use the exact trial methods', () => {
  const publicOrigin = 'https://metaguard.duckdns.org';
  const rawHeadersIn = [
    ['Host', 'metaguard.duckdns.org'], ['Referer', `${publicOrigin}/`],
    ['Sec-Fetch-Site', 'same-origin'], ['X-CSRF-Token', 'b'.repeat(43)],
  ];
  const account = request({ rawHeadersIn, uri: '/v1/auth/status' });
  assert.equal(origin.trialRoute(account), '1');
  assert.equal(origin.value(account), '');
  const report = request({ rawHeadersIn, uri: '/v1/reports/123e4567-e89b-12d3-a456-426614174000' });
  assert.equal(origin.trialRoute(report), '1');
  assert.equal(origin.value(report), publicOrigin);
  for (const uri of ['/v1/auth/register', '/v1/auth/verify-email', '/v1/auth/login/email', '/v1/auth/password-reset/request', '/v1/uploads/', '/v1/%75ploads']) {
    assert.equal(origin.trialRoute(request({ rawHeadersIn, uri, method: 'POST' })), '0');
  }
  assert.equal(origin.trialRoute(request({ rawHeadersIn, uri: '/v1/uploads', method: 'GET' })), '0');
  assert.equal(origin.trialRoute(request({ rawHeadersIn, uri: '/v1/uploads', method: 'POST' })), '1');
  assert.equal(origin.value(request({ rawHeadersIn, uri: '/v1/uploads', method: 'POST' })), '');
  assert.equal(origin.trialRoute(request({ rawHeadersIn: good, uri: '/v1/auth/status' })), '0');
});
