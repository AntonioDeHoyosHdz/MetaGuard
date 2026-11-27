#!/usr/bin/env bash
# Install a limited registration preview without changing the public frontend for other visitors.
# Standard input: base64 lines for the public upstream certificate and two Nginx includes.
set -euo pipefail
umask 077
test "$(id -u)" = 0
test "$(hostname -s)" = ip-172-31-29-108
test "$#" = 1
operator=$1
[[ "$operator" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]

config=/etc/metaguard-public/nginx.conf
trial=/etc/metaguard-public/account-trial.conf
frontend=/opt/metaguard-public/frontend
state=/etc/metaguard-public/registration-preview
service=metaguard-public-web.service
test ! -e "$state" && test ! -e "$frontend/registration-preview.html"
test -f "$config" && test ! -L "$config" && test -f "$frontend/index.html"
test "$(awk '$1 == "allow" && $2 ~ /^[0-9.]+\/32;$/ {print $2}' "$trial")" = "$operator/32;"
systemctl is-active --quiet "$service"

scratch=$(mktemp -d /tmp/metaguard-registration-web-XXXXXX)
rollback=0
cleanup() {
    if [ "$rollback" = 1 ]; then
        cp -a -- "$backup/nginx.conf" "$config"
        if nginx -t -c "$config" >/dev/null 2>&1; then
            nginx -s reload -c "$config" >/dev/null 2>&1 || true
        fi
        echo 'Preview not activated; previous frontend configuration restored.' >&2
    fi
    rm -rf -- "$scratch"
}
trap cleanup EXIT
for part in ca.pem http.conf server.conf; do
    IFS= read -r encoded
    printf '%s' "$encoded" | tr -d '\r' | base64 -d > "$scratch/$part"
done
openssl verify -purpose sslserver -verify_hostname metaguard-registration.internal \
    -CAfile "$scratch/ca.pem" "$scratch/ca.pem" >/dev/null

status=$(curl --noproxy '*' -sS --max-time 4 -o /dev/null -w '%{http_code}' --cacert "$scratch/ca.pem" \
    --resolve metaguard-registration.internal:8011:172.31.22.162 \
    -H 'Host: metaguard.duckdns.org' https://metaguard-registration.internal:8011/v1/auth/status)
test "$status" = 200

python3 - "$scratch" "$config" "$frontend/index.html" "$operator" "$state" <<'PY'
from pathlib import Path
import html
import re
import sys

scratch, config, index = map(Path, sys.argv[1:4])
operator, state = sys.argv[4:6]

http = scratch / "http.conf"
http.write_text(http.read_text().replace("__REGISTRATION_CLIENT_IPV4__", operator))
with http.open("a", encoding="utf-8") as handle:
    handle.write(f"\nmap $remote_addr $metaguard_preview_html {{\n"
                 f"    default /index.html;\n    {operator} /registration-preview.html;\n}}\n")

server = scratch / "server.conf"
server.write_text(server.read_text().replace("__REGISTRATION_CLIENT_IPV4__", operator)
                  .replace("__REGISTRATION_BACKEND_PRIVATE_IPV4__", "172.31.22.162")
                  .replace("__REGISTRATION_CA_FILE__", f"{state}/ca.pem"))

text = config.read_text()
http_anchor = "http {"
trial_anchor = "include /etc/metaguard-public/account-trial.conf;"
if text.count(http_anchor) != 1 or text.count(trial_anchor) != 1:
    raise SystemExit("Unexpected public Nginx configuration; preview not installed")
text = text.replace(http_anchor, f"{http_anchor}\n    include {state}/http.conf;", 1)
text = text.replace(trial_anchor, f"{trial_anchor}\n        include {state}/server.conf;", 1)
for route, old_target in [("/", "/index.html"), ("/index.html", "$uri"), ("/security/events", "/index.html")]:
    key = f'location = {route} {{ if ($request_method !~ "^(GET|HEAD)$") {{ return 405; }} '
    old = key + f"try_files {old_target} =404; }}"
    if text.count(old) != 1:
        raise SystemExit("Unexpected static route; preview not installed")
    text = text.replace(old, key + "try_files $metaguard_preview_html =404; }", 1)
(scratch / "nginx.conf").write_text(text)

address = html.escape("jarassanchezl@gmail.com", quote=True)
notice = (
    '<aside aria-label="Prueba de registro de MetaGuard">'
    '<p><strong>Prueba privada de cuentas.</strong> Usa un correo que controles y una contraseña '
    'exclusiva para esta prueba. MetaGuard utiliza el correo para enviar un código de un solo uso '
    'por Gmail y conserva el correo, la huella de la contraseña y los datos mínimos de sesión '
    'en la base aislada de prueba. No subas archivos. '
    f'Para solicitar el borrado de la cuenta o hacer una consulta, escribe a <a href="mailto:{address}">{address}</a>.</p>'
    '</aside>'
)
entry, substitutions = re.subn(r"<body(?:\s[^>]*)?>", lambda match: match.group(0) + notice,
                               index.read_text(encoding="utf-8"), flags=re.IGNORECASE)
if substitutions != 1:
    raise SystemExit("Unexpected frontend body; preview not installed")
(scratch / "registration-preview.html").write_text(entry, encoding="utf-8")
PY

install -d -m 0755 "$state"
for part in ca.pem http.conf server.conf; do install -m 0644 "$scratch/$part" "$state/$part"; done
install -m 0644 "$scratch/registration-preview.html" "$frontend/registration-preview.html"
nginx -t -c "$scratch/nginx.conf"
backup=$(mktemp -d /root/metaguard-registration-frontend-XXXXXX)
cp -a -- "$config" "$backup/nginx.conf"
rollback=1
install -m "$(stat -c %a "$config")" "$scratch/nginx.conf" "$state/active-nginx.conf"
mv -- "$state/active-nginx.conf" "$config"
nginx -s reload -c "$config"

probe() {
    curl --noproxy '*' --max-time 4 -sS -o "$scratch/response" -w '%{http_code}' \
        --resolve metaguard.duckdns.org:443:172.31.29.108 "https://metaguard.duckdns.org$1"
}
for path in / /index.html /security/events; do
    test "$(probe "$path")" = 200
    if grep -q 'Prueba privada de cuentas' "$scratch/response"; then exit 1; fi
done
test "$(probe /v1/auth/status)" = 403
rollback=0
printf 'frontend_preview=restricted_to_existing_operator\npublic_static_site=verified\nfrontend_rollback=%s\n' "$backup"
