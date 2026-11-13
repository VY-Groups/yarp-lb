#!/usr/bin/env bash
# Disposable localhost-only Kestrel HTTPS test certificate. Do not deploy on a
# public endpoint or a signing/RA/CA system. No purchased SSL certificate needed.
set -euo pipefail
umask 077
: "${DEV_PFX_PASSWORD:?Set DEV_PFX_PASSWORD for the local PFX output}"
dir="${1:-./.local-dev-cert}"
mkdir -p "$dir"
dir="$(cd "$dir" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 7 \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout "$tmp/localhost.key" -out "$dir/localhost.crt"
openssl pkcs12 -export -name localhost -inkey "$tmp/localhost.key" \
  -in "$dir/localhost.crt" -out "$dir/localhost.pfx" \
  -passout env:DEV_PFX_PASSWORD
chmod 600 "$dir/localhost.pfx"
echo "Generated localhost-only 7-day test certificate: $dir/localhost.pfx"
echo 'Trust the public localhost.crt manually in your LOCAL test machine only.'
echo 'Never commit PFX/private keys or use this for public/prod mTLS.'
