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

echo "[*] Instalando dependencias Python..."
pip3 install -r requirements.txt -q

echo "[*] Iniciando VPNPro Web Panel en puerto 5000..."
echo "[*] Directorio de datos del panel: ${PANEL_DATA_DIR}"
python3 app.py
