// Private staging only. Nginx installs this module alongside its staging config.
const authority = '127.0.0.1:8443';
const origin = 'https://' + authority;
const protectedRead = /^\/v1\/(?:security\/events|reports(?:\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})?)(?:\?[^#]*)?$/;
const strippedForwarding = ['x-forwarded-for', 'x-forwarded-host', 'x-forwarded-port', 'x-forwarded-proto'];

function header(r, name) {
  const values = [];
  for (let i = 0; i < r.rawHeadersIn.length; i += 1) {
    const pair = r.rawHeadersIn[i];
    if (pair[0].toLowerCase() === name) values.push(pair[1]);
  }
  return values;
}

function exactly(r, name, expected) {
  const values = header(r, name);
  return values.length === 1 && values[0] === expected;
}

function invalid(r) {
  const supplied = header(r, 'origin');
  if (supplied.length > 1 || (supplied.length === 1 && !supplied[0].trim())) return '1';
  for (let i = 0; i < r.rawHeadersIn.length; i += 1) {
    const key = r.rawHeadersIn[i][0].toLowerCase();
    if (key.indexOf('x-forwarded-') === 0 && strippedForwarding.indexOf(key) < 0) return '1';
  }
  return '0';
}

function value(r) {
  if (invalid(r) === '1') return '';
  const supplied = header(r, 'origin');
  if (supplied.length === 1) return supplied[0];
  if (r.variables.scheme !== 'https' || r.method !== 'GET' || !protectedRead.test(r.variables.request_uri) ||
      !exactly(r, 'host', authority) || !exactly(r, 'sec-fetch-site', 'same-origin')) return '';
  const referer = header(r, 'referer');
  const csrf = header(r, 'x-csrf-token');
  if (referer.length !== 1 || referer[0].indexOf(origin + '/') !== 0 ||
      csrf.length !== 1 || !/^[A-Za-z0-9_-]{43}$/.test(csrf[0])) return '';
  return origin;
}

export default { invalid: invalid, value: value };
