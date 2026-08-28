#!/usr/bin/env bash
# Generate the self-signed TLS certificate/key pair pirewall-api serves with
# (docs/DEPLOYMENT.md §6, spec §29).
#
# Self-signed is appropriate here and not a shortcut: the control panel is
# reachable only from one Admin PC on a LAN the Pi itself hosts, and there
# is no public name for a CA to attest to. What matters is that the traffic
# is encrypted and that `security.min_tls_version = "TLSv1.3"` is honoured
# — both of which a self-signed certificate provides. The Admin PC's
# browser will warn on first use; pin/accept the certificate once.
#
# Nothing here touches network configuration, systemd, or nftables — it
# writes two files and stops (spec §21, CLAUDE.md).
#
# Usage:
#   scripts/deployment/make_certs.sh <pi-lan-ip> [output-dir] [days]
# Example:
#   scripts/deployment/make_certs.sh 192.168.100.1
#
# The IP goes into the certificate's subjectAltName. Modern browsers and
# curl ignore the legacy Common Name entirely, so a certificate without a
# matching SAN fails verification even when you accept the warning — this
# is the single most common way a hand-rolled cert ends up unusable.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <pi-lan-ip> [output-dir] [days]" >&2
  exit 64
fi

LAN_IP="$1"
OUT_DIR="${2:-deploy/certificates}"
DAYS="${3:-825}"   # 825 days: the maximum lifetime browsers accept for a leaf cert

CERT_PATH="${OUT_DIR}/pirewall.crt"
KEY_PATH="${OUT_DIR}/pirewall.key"

if ! command -v openssl >/dev/null 2>&1; then
  echo "error: openssl not found on PATH" >&2
  exit 69
fi

if [[ -e "${CERT_PATH}" || -e "${KEY_PATH}" ]]; then
  echo "error: ${CERT_PATH} or ${KEY_PATH} already exists; refusing to overwrite." >&2
  echo "       Delete them deliberately first if you really mean to rotate." >&2
  exit 73
fi

mkdir -p "${OUT_DIR}"

# umask 077 so the key is never briefly world-readable between creation and
# chmod — there is no window to race.
# EC P-256 rather than RSA-4096: key generation is near-instant instead of
# tens of seconds on a Pi 4, the handshake is cheaper, and every TLS 1.3
# client supports it. RSA-4096 buys nothing here.
(
  umask 077
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes \
    -days "${DAYS}" \
    -keyout "${KEY_PATH}" \
    -out "${CERT_PATH}" \
    -subj "/CN=pirewall/O=pirewall" \
    -addext "subjectAltName=IP:${LAN_IP}" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "basicConstraints=critical,CA:FALSE"
)

chmod 600 "${KEY_PATH}"
chmod 644 "${CERT_PATH}"

cat <<EOF

Wrote:
  ${CERT_PATH}  (mode 644)
  ${KEY_PATH}  (mode 600)

Both are gitignored (.gitignore "Secrets / certificates") — never commit them.

On the Pi, the key must be readable by the pirewall-api service user and by
nobody else:

  sudo chown pirewall-api:pirewall-api ${KEY_PATH} ${CERT_PATH}
  sudo chmod 600 ${KEY_PATH}

Then confirm pirewall-api accepts them:

  uv run python -m pirewall.api --config config/local_config.toml --check-config

And from the Admin PC (expect a self-signed warning, hence --insecure):

  curl --insecure https://${LAN_IP}:8443/api/v1/health
EOF
