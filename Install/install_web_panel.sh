#!/usr/bin/env bash

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] Ejecuta como root: sudo bash install_web_panel.sh"
  exit 1
fi

REPO_URL="https://github.com/DiegoPintoTeam/VPNPro.git"
BASE_DIR="/opt/vpnpro-web-panel"
PANEL_DIR="${BASE_DIR}/web_panel"
VENV_DIR="${BASE_DIR}/.venv"
SERVICE_FILE="/etc/systemd/system/vpnpro-web.service"
ENV_FILE="/etc/default/vpnpro-web"

AUTO_SYNC_ENABLED="${AUTO_SYNC_ENABLED:-true}"
AUTO_SYNC_INTERVAL_MINUTES="${AUTO_SYNC_INTERVAL_MINUTES:-30}"
WEB_PANEL_PORT="${WEB_PANEL_PORT:-80}"

export DEBIAN_FRONTEND=noninteractive

echo "[*] Instalando dependencias del sistema..."
apt-get update -y
apt-get install -y git python3 python3-venv

echo "[*] Descargando/actualizando VPNPro..."
if [[ -d "${BASE_DIR}/.git" ]]; then
  git -C "${BASE_DIR}" fetch --all --prune
  git -C "${BASE_DIR}" reset --hard origin/main
else
  rm -rf "${BASE_DIR}"
  git clone --depth 1 "${REPO_URL}" "${BASE_DIR}"
fi

echo "[*] Creando entorno virtual Python..."
python3 -m venv "${VENV_DIR}"

echo "[*] Instalando dependencias Python del panel..."
"${VENV_DIR}/bin/pip" install --upgrade pip
"${VENV_DIR}/bin/pip" install -r "${PANEL_DIR}/requirements.txt"

echo "[*] Configurando servicio systemd..."
cat > "${ENV_FILE}" <<EOF
AUTO_SYNC_ENABLED=${AUTO_SYNC_ENABLED}
AUTO_SYNC_INTERVAL_MINUTES=${AUTO_SYNC_INTERVAL_MINUTES}
WEB_PANEL_PORT=${WEB_PANEL_PORT}
EOF

cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=VPNPro Web Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=${PANEL_DIR}
ExecStart=${VENV_DIR}/bin/python ${PANEL_DIR}/app.py
Restart=always
RestartSec=3
User=root
EnvironmentFile=-${ENV_FILE}
Environment=PYTHONUNBUFFERED=1
Environment=AUTO_SYNC_ENABLED=${AUTO_SYNC_ENABLED}
Environment=AUTO_SYNC_INTERVAL_MINUTES=${AUTO_SYNC_INTERVAL_MINUTES}
Environment=WEB_PANEL_PORT=${WEB_PANEL_PORT}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vpnpro-web.service
systemctl restart vpnpro-web.service

IP_ADDR="$(hostname -I 2>/dev/null | awk '{print $1}')"

echo "[+] Instalacion finalizada"
echo "[+] Servicio activo: vpnpro-web.service"
echo "[+] Auto-sync: ${AUTO_SYNC_ENABLED} | intervalo: ${AUTO_SYNC_INTERVAL_MINUTES} min"
if [[ -n "${IP_ADDR}" ]]; then
  echo "[+] Accede en: http://${IP_ADDR}:${WEB_PANEL_PORT}"
else
  echo "[+] Accede en: http://TU_IP_VPS:${WEB_PANEL_PORT}"
fi
echo "[+] Usuario: VPNPro"
echo "[+] Clave: 123456"
