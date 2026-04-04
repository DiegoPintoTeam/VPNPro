# VPNPro

### Instalacion

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/DiegoPintoTeam/VPNPro/main/Install/install_web_panel.sh)
```

### Activar UDP

```
wget https://github.com/DiegoPintoTeam/VPNPro/raw/main/Install/badvpn-udpgw -O /usr/bin/badvpn-udpgw && chmod +x /usr/bin/badvpn-udpgw && echo "[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000
Restart=always

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/badvpn.service && systemctl daemon-reload && systemctl enable badvpn && systemctl start badvpn && echo -e "\n\033[0;32mINSTALACIÓN COMPLETADA: BadVPN corriendo en el puerto 7300\033[0m\n"
```

El instalador realiza automaticamente:

- Instalacion de dependencias del sistema y Python
- Clonacion del repositorio en `/opt/vpnpro-web-panel`
- Registro y activacion del servicio `vpnpro-web.service` en systemd

### Acceso inicial

| Campo | Valor |
|---|---|
| URL | `http://TU_IP_VPS:5000` |
| Usuario | `VPNPro` |
| Contrasena | `123456` |

> Cambia las credenciales desde el dashboard despues del primer ingreso.

<p align="center">
  Desarrollado por <strong>Diego Pinto (Team)</strong> &nbsp;·&nbsp;
  Telegram: <a href="https://t.me/DiegoPintoTM">@DiegoPintoTM</a>
</p>

