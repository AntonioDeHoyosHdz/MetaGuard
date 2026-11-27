import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const fragment = readFileSync(new URL('./registration-preview-http.nginx.conf', import.meta.url), 'utf8');

test('only the intended literal routes enter the operator account and shared mail classes', () => {
  const routeMap = fragment.match(
    /^map "\$request_method:\$request_uri" \$metaguard_registration_route \{\r?\n([\s\S]+?)^\}/m,
  );
  assert.ok(routeMap, 'expected the registration preview route map');
  assert.deepEqual(routeMap[1].trim().split(/\r?\n/).map(line => line.trim()), [
    'default blocked;',
    '~^GET:/v1/auth/status$ account;',
    '~^POST:/v1/auth/(verify-email|login|logout)$ account;',
    '~^POST:/v1/auth/(register|resend-verification)$ mail;',
    '~^POST:/v1/auth/password-reset/request$ mail;',
    '~^POST:/v1/auth/password-reset/confirm$ account;',
  ]);
});

test('the mail class shares the existing per-source and total limits', () => {
  assert.match(fragment, /map \$metaguard_registration_route \$metaguard_registration_mail_ip \{\s+default "";\s+mail \$binary_remote_addr;\s+\}/);
  assert.match(fragment, /map \$metaguard_registration_route \$metaguard_registration_mail_total \{\s+default "";\s+mail registration-preview;\s+\}/);
  assert.match(fragment, /^limit_req_zone \$metaguard_registration_mail_ip zone=registration_mail_ip:1m rate=2r\/m;$/m);
  assert.match(fragment, /^limit_req_zone \$metaguard_registration_mail_total zone=registration_mail_total:1m rate=2r\/m;$/m);
});
