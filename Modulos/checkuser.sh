#!/bin/bash

url='https://github.com/DiegoPintoTeam/DTCheckUser.git'
depends=('git' 'python3' 'python3-pip' 'python3-venv')
VENV_PATH="/opt/checkuser_venv"

cd ~

checkuser_service() {
    local _port=$1
    # Apuntamos directamente al ejecutable dentro del entorno virtual
    local _cmd="${VENV_PATH}/bin/checkuser"

    cat <<EOF >/etc/systemd/system/checkuser.service
[Unit]
Description=CheckUser Service
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=${_cmd} --port ${_port} --start
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF
}

function install_dependencies() {
    echo '[*] Actualizando repositorios...'
    sudo apt update -y &>/dev/null
    for depend in "${depends[@]}"; do
        if ! dpkg -s $depend &>/dev/null; then
            echo "Instalando $depend..."
            sudo apt install -y $depend
        fi
    done
}

function install_checkuser() {
    if [[ -d DTCheckUser ]]; then
        rm -rf DTCheckUser
    fi

    echo '[*] Clonando DTCheckUser...'
    git clone $url &>/dev/null
    
    # Crear entorno virtual para evitar el error de PEP 668 en Ubuntu 24
    echo '[*] Configurando entorno virtual Python...'
    sudo python3 -m venv $VENV_PATH
    
    cd DTCheckUser
    echo '[*] Instalando dependencias en venv...'
    sudo ${VENV_PATH}/bin/pip install -r requirements.txt &>/dev/null
    echo '[*] Instalando DTCheckUser...'
    sudo ${VENV_PATH}/bin/python3 setup.py install &>/dev/null
    
    cd ..
    rm -rf DTCheckUser
    echo '[+] DTCheckUser instalado en '$VENV_PATH'!'
}

function start_checkuser() {
    echo '[*] Iniciando DTCheckUser...'
    local port="$1"
    if [[ -z "$port" ]]; then
        read -p 'Puerto: ' -e -i 2052 port
    fi

    if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
        echo '[!] Puerto invalido. Debe estar entre 1 y 65535.'
        return 1
    fi
    
    checkuser_service $port
    
    systemctl daemon-reload
    systemctl enable checkuser.service
    systemctl start checkuser.service

    addr=$(curl -s icanhazip.com)
    echo "URL: http://${addr}:${port}"
    if [[ -t 0 ]]; then
        read -p "Presione ENTER para continuar..."
    fi
}

function uninstall_checkuser() {
    echo '[*] Parando DTCheckUser...'
    systemctl stop checkuser &>/dev/null
    systemctl disable checkuser &>/dev/null
    rm -f /etc/systemd/system/checkuser.service &>/dev/null
    systemctl daemon-reload &>/dev/null

    echo '[*] Eliminando archivos y entorno virtual...'
    sudo rm -rf $VENV_PATH
    
    echo '[+] DTCheckUser desinstalado!'
    if [[ -t 0 ]]; then
        read -p "Presione ENTER para continuar..."
    fi
}

# --- Resto de funciones de lógica de menú (se mantienen similares) ---

function is_installed() {
    [[ -f "${VENV_PATH}/bin/checkuser" ]]
}

function get_version() {
    if is_installed; then
        echo "$(${VENV_PATH}/bin/checkuser --version 2>/dev/null | cut -d ' ' -f 2)"
    else
        echo '-1'
    fi
}

function start_process_install() {
    local port="$1"
    install_dependencies
    install_checkuser
    start_checkuser "$port"
}

function reinstall_checkuser() {
    local port="$1"
    uninstall_checkuser
    install_checkuser
    start_checkuser "$port"
}

function console_menu() {
    clear
    echo -n 'CHECKUSER MENU v1 (Ubuntu 24 Edition) - '
    if is_installed; then
        echo -e '\e[32m[INSTALADO]\e[0m - Version:' $(get_version)
    else
        echo -e '\e[31m[DESINSTALADO]\e[0m'
    fi
    echo
    echo '[01] - INSTALAR'
    echo '[02] - REINSTALAR'
    echo '[03] - DESINSTALAR'
    echo '[00] - SALIR'
    echo
    read -p 'Elige una opción: ' option
    case $option in
        01|1) start_process_install; console_menu ;;
        02|2) reinstall_checkuser; console_menu ;;
        03|3) uninstall_checkuser; console_menu ;;
        00|0) exit 0 ;;
        *) echo 'Opción no válida!'; sleep 1; console_menu ;;
    esac
}

if [[ $# -eq 0 ]]; then
    console_menu
else
    case $1 in
        install|-i) start_process_install "$2" ;;
        reinstall|-r) reinstall_checkuser "$2" ;;
        uninstall|-u) uninstall_checkuser ;;
        *) echo "Uso: $0 [install|reinstall|uninstall] [puerto-opcional]"; exit 1 ;;
    esac
fi
