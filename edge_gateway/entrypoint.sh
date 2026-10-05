#!/bin/sh
set -eu

: "${CLOUD_URL:=http://cloud:8000}"
: "${CLOUD_KEY_FINGERPRINT:?CLOUD_KEY_FINGERPRINT must be set; retrieve it from the cloud /health endpoint}"

fingerprint_length=$(printf %s "$CLOUD_KEY_FINGERPRINT" | wc -c | tr -d ' ')
case "$CLOUD_KEY_FINGERPRINT" in
  *[!0-9a-fA-F]*|'')
    echo "CLOUD_KEY_FINGERPRINT must be exactly 64 hexadecimal characters" >&2
    exit 64
    ;;
esac
if [ "$fingerprint_length" -ne 64 ]; then
  echo "CLOUD_KEY_FINGERPRINT must be exactly 64 hexadecimal characters" >&2
  exit 64
fi

exec python -m edge_gateway.gateway \
  --host "${GATEWAY_HOST:-0.0.0.0}" \
  --port "${GATEWAY_PORT:-9000}" \
  --cloud-url "$CLOUD_URL" \
  --crypto "${CRYPTO_MODE:-mlkem}" \
  --cloud-key-fingerprint "$CLOUD_KEY_FINGERPRINT"
