#!/usr/bin/env bash

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] Ejecuta este script como root"
  exit 1
fi

PANEL_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_BIN="$(command -v python3 || true)"
ENV_FILE="/etc/default/vpnpro-web"
PANEL_DATA_DIR="${PANEL_DATA_DIR:-/var/lib/vpnpro-web}"

AUTO_SYNC_ENABLED="${AUTO_SYNC_ENABLED:-true}"
AUTO_SYNC_INTERVAL_MINUTES="${AUTO_SYNC_INTERVAL_MINUTES:-30}"
WEB_PANEL_PORT="${WEB_PANEL_PORT:-80}"

if [[ -z "${PYTHON_BIN}" ]]; then
  echo "[!] python3 no esta instalado"
  exit 1
fi

echo "[*] Instalando dependencias del panel..."
"${PYTHON_BIN}" -m pip install -r "${PANEL_DIR}/requirements.txt"

echo "[*] Preparando almacenamiento persistente del panel..."
mkdir -p "${PANEL_DATA_DIR}"

echo "[*] Escribiendo configuracion persistente de auto-sync..."
cat > "${ENV_FILE}" <<EOF
AUTO_SYNC_ENABLED=${AUTO_SYNC_ENABLED}
AUTO_SYNC_INTERVAL_MINUTES=${AUTO_SYNC_INTERVAL_MINUTES}
PANEL_DATA_DIR=${PANEL_DATA_DIR}
WEB_PANEL_PORT=${WEB_PANEL_PORT}
EOF

echo "[*] Creando servicio systemd: vpnpro-web.service"
cat > /etc/systemd/system/vpnpro-web.service <<EOF
[Unit]
Description=VPNPro Web Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=${PANEL_DIR}
ExecStart=${PYTHON_BIN} ${PANEL_DIR}/app.py
Restart=always
RestartSec=3
User=root
EnvironmentFile=-${ENV_FILE}
Environment=PYTHONUNBUFFERED=1
Environment=AUTO_SYNC_ENABLED=${AUTO_SYNC_ENABLED}
Environment=AUTO_SYNC_INTERVAL_MINUTES=${AUTO_SYNC_INTERVAL_MINUTES}
Environment=PANEL_DATA_DIR=${PANEL_DATA_DIR}
Environment=WEB_PANEL_PORT=${WEB_PANEL_PORT}

[Install]
WantedBy=multi-user.target
EOF

echo "[*] Recargando systemd..."
systemctl daemon-reload

echo "[*] Habilitando arranque automatico..."
systemctl enable vpnpro-web.service

echo "[*] Iniciando servicio..."
systemctl restart vpnpro-web.service

echo "[*] Estado actual del servicio:"
systemctl --no-pager --full status vpnpro-web.service || true

echo "[+] Auto-sync: ${AUTO_SYNC_ENABLED} | intervalo: ${AUTO_SYNC_INTERVAL_MINUTES} min"
echo "[+] Datos persistentes del panel: ${PANEL_DATA_DIR}"

echo "[+] Listo. El panel quedara activo despues de reiniciar."