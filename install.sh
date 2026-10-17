#!/bin/bash
# fuzzpot install script — creates system user, copies binary, installs service
set -euo pipefail

BINDIR="/opt/fuzzpot"
CONFDIR="/etc/fuzzpot"
LOGDIR="/var/log/fuzzpot"
SERVICE="/etc/systemd/system/fuzzpot.service"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Run as root directly (sudo ./install.sh) or prefix privileged commands with sudo
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

echo "=== fuzzpot install ==="

# 1. Create unprivileged system user
if ! id fuzzpot &>/dev/null; then
    echo "[*] Creating user 'fuzzpot'..."
    $SUDO useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin --no-create-home fuzzpot
else
    echo "[*] User 'fuzzpot' already exists"
fi

# 2. Install binary
echo "[*] Installing binary to ${BINDIR}..."
$SUDO mkdir -p "${BINDIR}"
$SUDO cp "${SCRIPT_DIR}/fuzzpot" "${BINDIR}/fuzzpot"
$SUDO chmod 755 "${BINDIR}/fuzzpot"

# 3. Install config
echo "[*] Installing config to ${CONFDIR}..."
$SUDO mkdir -p "${CONFDIR}"
if [ ! -f "${CONFDIR}/config.yaml" ]; then
    $SUDO cp "${SCRIPT_DIR}/config/config.yaml" "${CONFDIR}/config.yaml"
    $SUDO chmod 640 "${CONFDIR}/config.yaml"
    $SUDO chown fuzzpot:fuzzpot "${CONFDIR}/config.yaml"
else
    echo "[*] Config already exists, skipping (edit manually)"
fi

# 4. Create log directory
echo "[*] Creating log directory ${LOGDIR}..."
$SUDO mkdir -p "${LOGDIR}"
$SUDO chown fuzzpot:fuzzpot "${LOGDIR}"
$SUDO chmod 750 "${LOGDIR}"

# 5. Install systemd service
echo "[*] Installing systemd service..."
$SUDO cp "${SCRIPT_DIR}/fuzzpot.service" "${SERVICE}"
$SUDO systemctl daemon-reload

echo ""
echo "=== Installation complete ==="
echo ""
echo "  Binary:   ${BINDIR}/fuzzpot"
echo "  Config:   ${CONFDIR}/config.yaml"
echo "  Logs:     ${LOGDIR}/"
echo "  Service:  fuzzpot.service"
echo ""
echo "Commands:"
echo "  sudo systemctl enable --now fuzzpot   # start + enable on boot"
echo "  sudo systemctl status fuzzpot         # check status"
echo "  journalctl -u fuzzpot -f              # live logs"
echo "  sudo systemctl stop fuzzpot           # stop"
echo ""
