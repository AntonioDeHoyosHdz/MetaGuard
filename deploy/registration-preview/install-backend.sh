#!/usr/bin/env bash
# MetaGuard EC2 operator-only preview. Standard input: base64 of the verified source archive.
set -euo pipefail
umask 077

[[ $# == 2 && $1 =~ ^[a-f0-9]{64}$ && $2 =~ ^[a-z0-9]+(\.[a-z0-9]+)*@gmail\.com$ ]]
test "$(id -u)" = 0
test "$(hostname -s)" = ip-172-31-22-162

root=/opt/metaguard-registration-preview
secrets=/etc/metaguard-registration-private
service=metaguard-registration-preview.service
unit=/etc/systemd/system/$service
gmail=/etc/metaguard-mail-smoke/gmail_app_password
source_venv=/opt/metaguard-staging/venv
test ! -e "$root" && test ! -e "$unit"
test -z "$(ss -Hltn 'sport = :8011')"
for item in jwt_signing_key totp_encryption_key ingress.key; do test ! -e "$secrets/$item"; done
for file in "$gmail" "$secrets/postgres_password"; do
    test -f "$file" && test ! -L "$file" && test "$(stat -c '%a:%U' "$file")" = 600:root
done
test -x "$source_venv/bin/python"
if nft list table inet metaguard_registration_preview >/dev/null 2>&1; then
    echo 'Preview firewall table already exists; no changes made.' >&2
    exit 1
fi

scratch=$(mktemp -d /tmp/metaguard-registration-backend-XXXXXX)
armed=0
cleanup() {
    if [ "$armed" = 1 ]; then
        systemctl stop "$service" >/dev/null 2>&1 || true
        nft delete table inet metaguard_registration_preview >/dev/null 2>&1 || true
        echo 'Preview stopped; staging and the public frontend were not changed.' >&2
    fi
    rm -rf -- "$scratch"
}
trap cleanup EXIT
tr -d '\r\n' | base64 -d > "$scratch/source.tar"
printf '%s  %s\n' "$1" "$scratch/source.tar" | sha256sum -c --status
mkdir "$scratch/app"
python3 - "$scratch/source.tar" "$scratch/app" <<'PY'
from pathlib import PurePosixPath
import sys
import tarfile

with tarfile.open(sys.argv[1], mode="r:") as source:
    members = source.getmembers()
    if not members or len(members) > 128:
        raise SystemExit("Unexpected archive size")
    for member in members:
        name = PurePosixPath(member.name)
        if (
            not member.isfile()
            or len(name.parts) != 2
            or name.parts[0] != "metaguard_api"
            or name.suffix != ".py"
            or member.size > 256 * 1024
        ):
            raise SystemExit("Archive includes an unexpected entry")
    source.extractall(sys.argv[2], filter="data")
PY

# The credential is not read in this TLS-only preflight. Use a fixed verified IPv4 endpoint.
gmail_ip=''
while IFS= read -r candidate; do
    if [ -z "$candidate" ]; then continue; fi
    if timeout 6 openssl s_client -brief -verify_return_error -verify_hostname smtp.gmail.com \
        -servername smtp.gmail.com -connect "$candidate:465" </dev/null >/dev/null 2>&1; then
        gmail_ip=$candidate
        break
    fi
done < <(getent ahostsv4 smtp.gmail.com | awk '{print $1}' | sort -u | head -n 3)
[[ "$gmail_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]

install -d -m 0755 "$root"
cp -a "$scratch/app" "$root/app"
cp -a "$source_venv" "$root/venv"
chmod -R a+rX "$root/app" "$root/venv"
install -m 0644 /etc/metaguard-staging/tls/db-ca.pem "$root/db-ca.pem"
printf '127.0.0.1 localhost\n%s smtp.gmail.com\n' "$gmail_ip" > "$root/smtp-hosts"
# An initial blocklist for a limited operator preview, not for a public launch.
printf '%s\n' passwordpassword 123456789012345 adminadminadminadmin qwertyuiopasdfgh 'correct horse battery staple' > "$root/preview-blocklist"
chmod 0644 "$root/smtp-hosts" "$root/preview-blocklist"
( set -C; openssl rand -hex 48 > "$secrets/jwt_signing_key"; openssl rand 32 > "$secrets/totp_encryption_key" )
openssl req -x509 -newkey ed25519 -nodes -days 7 \
    -keyout "$secrets/ingress.key" -out "$root/ingress.pem" \
    -subj /CN=metaguard-registration.internal \
    -addext subjectAltName=DNS:metaguard-registration.internal \
    -addext basicConstraints=critical,CA:FALSE -addext extendedKeyUsage=serverAuth >/dev/null 2>&1
chmod 0600 "$secrets/ingress.key"
chmod 0644 "$root/ingress.pem"
openssl verify -purpose sslserver -verify_hostname metaguard-registration.internal \
    -CAfile "$root/ingress.pem" "$root/ingress.pem" >/dev/null

cat > "$scratch/guard.nft" <<'NFT'
table inet metaguard_registration_preview {
    chain input {
        type filter hook input priority -21; policy accept;
        iifname "ens5" ip saddr 172.31.29.108 ip daddr 172.31.22.162 tcp dport 8011 accept
        tcp dport 8011 drop
    }
}
NFT
nft -c -f "$scratch/guard.nft"
install -m 0600 "$scratch/guard.nft" "$secrets/guard.nft"
cat > "$scratch/$service" <<UNIT
[Unit]
Description=MetaGuard operator-only registration preview
After=network-online.target

[Service]
Type=simple
DynamicUser=yes
WorkingDirectory=$root/app
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_UNIX
IPAddressDeny=any
IPAddressAllow=172.31.29.108/32 172.31.26.1/32 $gmail_ip/32
BindReadOnlyPaths=$root/smtp-hosts:/etc/hosts
MemoryMax=512M
LimitNOFILE=160
Environment=METAGUARD_ENVIRONMENT=production
Environment=METAGUARD_AUTH_ALLOWED_ORIGINS=[\"https://metaguard.duckdns.org\"]
Environment=METAGUARD_SECRET_DIR=%d METAGUARD_DB_SECRET_DIR=%d
Environment=METAGUARD_DB_HOST=172.31.26.1 METAGUARD_DB_PORT=55432
Environment=METAGUARD_DB_NAME=metaguard_registration_trial METAGUARD_DB_USER=metaguard_registration_app
Environment=METAGUARD_REGISTRATION_PRIVATE_TRIAL=true METAGUARD_REGISTRATION_INGRESS_ENABLED=true
Environment=METAGUARD_REGISTRATION_INGRESS_PEER=172.31.29.108
Environment=METAGUARD_REGISTRATION_DB_TLS_CA=$root/db-ca.pem
Environment=METAGUARD_REGISTRATION_PASSWORD_BLOCKLIST=$root/preview-blocklist
Environment=METAGUARD_REGISTRATION_GMAIL_SENDER=$2
LoadCredential=postgres_password:$secrets/postgres_password
LoadCredential=jwt_signing_key:$secrets/jwt_signing_key
LoadCredential=totp_encryption_key:$secrets/totp_encryption_key
LoadCredential=gmail_app_password:$gmail
LoadCredential=ingress.key:$secrets/ingress.key
ExecStart=$root/venv/bin/python -B -m uvicorn metaguard_api.registration_trial:create_registration_ingress_app --app-dir $root/app --factory --host 172.31.22.162 --port 8011 --workers 1 --no-proxy-headers --no-access-log --log-level warning --limit-concurrency 12 --ssl-certfile $root/ingress.pem --ssl-keyfile %d/ingress.key
UNIT
systemd-analyze verify "$scratch/$service"
install -m 0644 "$scratch/$service" "$unit"
armed=1
nft -f "$secrets/guard.nft"
systemctl daemon-reload
systemctl start "$service"
timeout 10 sh -c 'until ss -Hltn "sport = :8011" | grep -q 172.31.22.162:8011; do sleep 0.2; done'
systemctl is-active --quiet "$service"
armed=0
printf 'preview_backend=active_on_private_8011\npreview_service_not_enabled_on_boot=yes\npreview_source=%s\n' "$1"
