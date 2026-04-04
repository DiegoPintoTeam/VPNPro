#!/usr/bin/env bash
# ============================================================
#  VPNPro Web Panel — Script de inicio rápido (Linux/VPS)
# ============================================================

set -e
cd "$(dirname "$0")"

# Auto-sync de usuarios servidor -> panel
export AUTO_SYNC_ENABLED="${AUTO_SYNC_ENABLED:-true}"
export AUTO_SYNC_INTERVAL_MINUTES="${AUTO_SYNC_INTERVAL_MINUTES:-30}"
export PANEL_DATA_DIR="${PANEL_DATA_DIR:-$(pwd)/instance}"
export WEB_PANEL_PORT="${WEB_PANEL_PORT:-80}"

echo "[*] Instalando dependencias Python..."
pip3 install -r requirements.txt -q

echo "[*] Iniciando VPNPro Web Panel en puerto ${WEB_PANEL_PORT}..."
echo "[*] Directorio de datos del panel: ${PANEL_DATA_DIR}"
python3 app.py
