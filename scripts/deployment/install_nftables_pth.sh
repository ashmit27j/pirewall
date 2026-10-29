#!/usr/bin/env bash
# Make Debian's python3-nftables importable from pirewall's uv venv (CLAUDE.md
# "v2 dependency additions").
#
# python3-nftables is ctypes over the system libnftables, so the package from
# the system interpreter works unchanged in the venv's Python 3.12. Rather
# than putting all of /usr/lib/python3/dist-packages on the venv's path
# (which would let any Debian module the venv lacks shadow-import into
# pirewall), this links *only* the `nftables` package into a private
# directory and adds that one directory with a .pth file:
#
#   <venv>/lib/pirewall-system-nftables/nftables -> <system>/nftables
#   <venv site-packages>/pirewall-system-nftables.pth  (one line: that directory)
#
# Idempotent: re-running replaces the link and the .pth. Then it verifies
# that the venv imports `nftables` and can create a libnftables context
# (no root needed for that; running commands needs CAP_NET_ADMIN).
#
# Without this, pirewall still works: the transport falls back to the
# `nft -j -f -` subprocess, and `pirewall-start --check` reports which
# transport is in use.
#
# Usage:
#   scripts/deployment/install_nftables_pth.sh [--venv DIR] [--system-python PATH] [--check] [--uninstall]
#     --venv DIR            the uv venv (default: /opt/pirewall/.venv)
#     --system-python PATH  the interpreter python3-nftables is installed for (default: /usr/bin/python3)
#     --check               verify only; change nothing
#     --uninstall           remove the link directory and the .pth
#
# Exit codes: 0 ok, 1 failed, 2 refused (missing prerequisite, bad usage).

set -euo pipefail

VENV="/opt/pirewall/.venv"
SYSTEM_PY="/usr/bin/python3"
MODE="install"
readonly PTH_NAME="pirewall-system-nftables.pth"
readonly LINK_DIR_NAME="pirewall-system-nftables"

usage() {
  sed -n '/^# Usage:/,/^# Exit codes/p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

refuse() { echo "install_nftables_pth: $*" >&2; exit 2; }
fail()   { echo "install_nftables_pth: $*" >&2; exit 1; }

while (( $# )); do
  case "$1" in
    --venv)          (( $# >= 2 )) || usage; VENV="$2"; shift ;;
    --system-python) (( $# >= 2 )) || usage; SYSTEM_PY="$2"; shift ;;
    --check)         MODE="check" ;;
    --uninstall)     MODE="uninstall" ;;
    -h|--help)       usage ;;
    *)               echo "unknown argument: $1" >&2; usage ;;
  esac
  shift
done

VENV_PY="${VENV}/bin/python"
[[ -x "$VENV_PY" ]] || refuse "no venv interpreter at ${VENV_PY} — create it first (uv sync --frozen), or pass --venv"

SITE="$("$VENV_PY" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')" \
  || fail "could not ask ${VENV_PY} for its site-packages directory"
LINK_DIR="${VENV}/lib/${LINK_DIR_NAME}"
PTH="${SITE}/${PTH_NAME}"

verify() {
  "$VENV_PY" - <<'PY'
import sys

try:
    import nftables
except ImportError as exc:
    print(f"FAIL: the venv cannot import nftables: {exc}")
    sys.exit(1)
try:
    nftables.Nftables()
except OSError as exc:
    print(f"FAIL: nftables imported from {nftables.__file__}, but libnftables did not load: {exc}")
    sys.exit(1)
print(f"ok: nftables from {nftables.__file__}; libnftables loaded (transport: libnftables)")
PY
}

if [[ "$MODE" == "check" ]]; then
  verify || fail "not installed — run without --check"
  exit 0
fi

if [[ "$MODE" == "uninstall" ]]; then
  rm -f "$PTH"
  rm -rf "$LINK_DIR"
  echo "removed ${PTH} and ${LINK_DIR}; the transport falls back to the nft subprocess"
  exit 0
fi

[[ -x "$SYSTEM_PY" ]] || refuse "no system interpreter at ${SYSTEM_PY}"
PACKAGE="$("$SYSTEM_PY" -c '
import os, nftables
path = nftables.__file__
print(os.path.dirname(path) if os.path.basename(path) == "__init__.py" else path)
' 2>/dev/null)" || refuse "python3-nftables is not installed for ${SYSTEM_PY}. Install it:  sudo apt install python3-nftables"

mkdir -p "$LINK_DIR"
ln -sfn "$PACKAGE" "${LINK_DIR}/$(basename "$PACKAGE")"
printf '%s\n' "$LINK_DIR" > "$PTH"
echo "linked ${PACKAGE} into ${LINK_DIR}; wrote ${PTH}"

verify || fail "installed, but the venv still cannot use nftables (see above)"
