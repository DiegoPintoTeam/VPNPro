#!/bin/bash

if [ "$EUID" -ne 0 ]; then 
  echo "❌ Por favor, ejecuta con sudo (sudo su)"
  exit
fi

echo "🚀 Iniciando configuración TOTAL para HTTP Injector..."

# 1. Optimizar SSH para compatibilidad con algoritmos antiguos (rsa-sha2-256)
echo "🔧 Ajustando configuración de SSH para compatibilidad..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i '/HostKeyAlgorithms/d' /etc/ssh/sshd_config
sed -i '/PubkeyAcceptedAlgorithms/d' /etc/ssh/sshd_config

cat << EOF >> /etc/ssh/sshd_config
# Compatibilidad con clientes SSH antiguos (HTTP Injector)
HostKeyAlgorithms +ssh-rsa,ssh-ed25519
PubkeyAcceptedAlgorithms +ssh-rsa,ssh-ed25519
KexAlgorithms +diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp256
EOF

systemctl restart ssh

# 2. Crear directorio y certificados SSL
echo "🔐 Generando certificados SSL..."
mkdir -p /etc/ssh-ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssh-ssl/selfsigned.key \
  -out /etc/ssh-ssl/selfsigned.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost"

# 3. Crear el script de Python (Túnel SSL)
echo "🐍 Creando puente Python SSL -> SSH..."
cat << 'EOF' > /usr/local/bin/ssh-ssl.py
import socket, threading, ssl

def tunnel(s1, s2):
    try:
        while True:
            d = s1.recv(8192)
            if not d: break
            s2.sendall(d)
    except: pass
    finally:
        try: s1.close()
        except: pass
        try: s2.close()
        except: pass

def handle_ssl(c):
    try:
        # Conexión al SSH local (puerto 22)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 22))
        
        # Puente bidireccional
        t1 = threading.Thread(target=tunnel, args=(c, s), daemon=True)
        t2 = threading.Thread(target=tunnel, args=(s, c), daemon=True)
        t1.start()
        t2.start()
    except:
        c.close()

def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Soporte para versiones TLS que usa Injector
    context.minimum_version = ssl.TLSVersion.TLSv1
    context.load_cert_chain(certfile="/etc/ssh-ssl/selfsigned.crt", keyfile="/etc/ssh-ssl/selfsigned.key")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 443))
    server.listen(100)

    with context.wrap_socket(server, server_side=True) as ssock:
        while True:
            try:
                conn, addr = ssock.accept()
                threading.Thread(target=handle_ssl, args=(conn,), daemon=True).start()
            except Exception:
                continue

if __name__ == "__main__":
    main()
EOF

chmod +x /usr/local/bin/ssh-ssl.py

# 4. Crear el servicio Systemd
echo "🔄 Creando servicio persistente..."
cat << EOF > /etc/systemd/system/ssh-ssl.service
[Unit]
Description=SSH SSL Tunnel para HTTP Injector
After=network.target

[Service]
Type=simple
ExecStartPre=-/usr/bin/fuser -k 443/tcp
ExecStart=/usr/bin/python3 /usr/local/bin/ssh-ssl.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

# 5. Firewall y Activación
echo "🛡️ Configurando Firewall..."
if command -v ufw > /dev/null; then
    ufw allow 443/tcp
    ufw allow 22/tcp
fi

systemctl daemon-reload
systemctl enable ssh-ssl
systemctl restart ssh-ssl

echo "---"
echo "✅ ¡TODO LISTO!"
echo "📍 Puerto SSL: 443"
echo "📍 SNI sugerido: facebook.com o m.google.com"
echo "⚠️ Recuerda activar 'Aceptar certificados inseguros' en HTTP Injector."
