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
#   scripts/deployment/make_certs.sh [-o output-dir] [-d days] <ip-or-dns-name>...
# Examples:
#   scripts/deployment/make_certs.sh 192.168.100.1
#   scripts/deployment/make_certs.sh 192.168.100.1 10.0.0.2 pirewall.lan
#
# Every name goes into the certificate's subjectAltName (KNOWN_ISSUES.md #9):
# IPv4/IPv6 addresses as IP entries, anything else as a DNS entry. List every
# address the Admin PC may connect to, e.g. the LAN and the admin-interface
# addresses on a three-interface Pi. Modern browsers and curl ignore the
# legacy Common Name entirely, so a certificate without a matching SAN fails
# verification even when you accept the warning — this is the single most
# common way a hand-rolled cert ends up unusable.
#
# The old positional form `<ip> [output-dir] [days]` is refused with a hint
# rather than guessed at: an output directory must never end up as a SAN.

set -euo pipefail

usage() {
  echo "usage: $0 [-o output-dir] [-d days] <ip-or-dns-name>..." >&2
  exit 64
}

OUT_DIR="deploy/certificates"
DAYS="825"   # 825 days: the maximum lifetime browsers accept for a leaf cert

while getopts ":o:d:h" opt; do
  case "${opt}" in
    o) OUT_DIR="${OPTARG}" ;;
    d) DAYS="${OPTARG}" ;;
    h) usage ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))

if [[ $# -lt 1 ]]; then
  usage
fi

if ! [[ "${DAYS}" =~ ^[1-9][0-9]{0,4}$ ]]; then
  echo "error: days must be a positive integer, got '${DAYS}'" >&2
  exit 64
fi

IPV4_RE='^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
IPV6_RE='^[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*$'
LABEL='[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
DNS_RE="^${LABEL}(\\.${LABEL})*\$"

# Each name is checked against a strict pattern before it reaches openssl:
# a comma or a stray keyword in one would otherwise add extensions to the
# certificate, because `-addext` parses the joined string.
SANS=()
for name in "$@"; do
  if [[ "${name}" =~ ${IPV4_RE} ]]; then
    SANS+=("IP:${name}")
  elif [[ "${name}" =~ ${IPV6_RE} ]]; then
    SANS+=("IP:${name}")
  elif [[ "${name}" == */* ]]; then
    echo "error: '${name}' looks like a path. The output directory is now -o: $0 -o ${name} <names>..." >&2
    exit 64
  elif [[ "${name}" =~ ^[0-9.]+$ ]]; then
    echo "error: '${name}' is neither a valid IPv4 address nor a DNS name (days are now -d)" >&2
    exit 64
  elif [[ "${name}" =~ ${DNS_RE} ]] && [[ ${#name} -le 253 ]]; then
    SANS+=("DNS:${name}")
  else
    echo "error: '${name}' is neither an IP address nor a valid DNS name" >&2
    exit 64
  fi
done
SAN_LIST="$(IFS=,; echo "${SANS[*]}")"
FIRST_NAME="$1"

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
    -addext "subjectAltName=${SAN_LIST}" \
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
  subjectAltName: ${SAN_LIST}

Both are gitignored (.gitignore "Secrets / certificates") — never commit them.

On the Pi, the key must be readable by the pirewall-api service user and by
nobody else:

  sudo chown pirewall-api:pirewall-api ${KEY_PATH} ${CERT_PATH}
  sudo chmod 600 ${KEY_PATH}

Then confirm pirewall-api accepts them:

  uv run python -m pirewall.api --config config/local_config.toml --check-config

And from the Admin PC (expect a self-signed warning, hence --insecure):

  curl --insecure https://${FIRST_NAME}:8443/api/v1/health
EOF
