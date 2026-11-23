#!/bin/sh
# Certbot executes deployment hooks as root. Restrict reload to this lineage.
set -eu
lineage=/etc/letsencrypt/live/metaguard.duckdns.org
case "${RENEWED_LINEAGE:-}" in
    "$lineage") ;;
    *) exit 0 ;;
esac

/usr/bin/openssl verify -purpose sslserver -verify_hostname metaguard.duckdns.org \
    -CApath /etc/ssl/certs -untrusted "$lineage/chain.pem" "$lineage/cert.pem"
/usr/bin/systemctl reload metaguard-public-web.service
