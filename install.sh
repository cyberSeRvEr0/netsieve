#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$(id -u)" -eq 0 ]]; then
    echo "Run this installer as your normal user; it will ask sudo to install system packages." >&2
    exit 1
fi

if [[ ! -r /etc/os-release ]]; then
    echo "Cannot identify this Linux distribution. This installer supports Ubuntu and Debian." >&2
    exit 1
fi

. /etc/os-release
case "${ID:-} ${ID_LIKE:-}" in
    *ubuntu*|*debian*) ;;
    *)
        echo "This installer supports Ubuntu and Debian-based systems only." >&2
        exit 1
        ;;
esac

if ! command -v sudo >/dev/null 2>&1 || ! command -v apt-get >/dev/null 2>&1; then
    echo "This installer requires sudo and apt-get." >&2
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

echo "Installing operating-system requirements..."
sudo -v
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip iptables traceroute

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    echo "NetSieve requires Python 3.10 or newer. Install a newer Python and rerun this script." >&2
    exit 1
fi

echo "Creating the NetSieve Python environment..."
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/python" -m pip install -e "$SCRIPT_DIR"

echo "Creating the default NetSieve configuration..."
"$VENV_DIR/bin/netsieve" setup

LAUNCHER="/usr/local/bin/netsieve"
if [[ -e "$LAUNCHER" || -L "$LAUNCHER" ]]; then
    if [[ "$(readlink -f -- "$LAUNCHER")" != "$(readlink -f -- "$VENV_DIR/bin/netsieve")" ]]; then
        echo "Not changing existing $LAUNCHER. Use $VENV_DIR/bin/netsieve if it points elsewhere."
    fi
else
    sudo ln -s "$VENV_DIR/bin/netsieve" "$LAUNCHER"
fi

echo
echo "NetSieve is installed."
echo "Try: netsieve --help"
echo "Privileged example: sudo netsieve detect -d 30"
