#!/bin/bash

if [ "$EUID" -ne 0 ]; then 
  echo "❌ Ejecuta como sudo"
  exit
fi

echo "🌐 Configurando Túnel WebSocket para HTTP Injector..."

# 1. Asegurar compatibilidad SSH (necesario para Injector)
echo "🔧 Ajustando SSH..."
sed -i '/HostKeyAlgorithms/d' /etc/ssh/sshd_config
sed -i '/PubkeyAcceptedAlgorithms/d' /etc/ssh/sshd_config
cat << EOF >> /etc/ssh/sshd_config
HostKeyAlgorithms +ssh-rsa,ssh-ed25519
PubkeyAcceptedAlgorithms +ssh-rsa,ssh-ed25519
EOF
systemctl restart ssh

# 2. Crear el script de Python para WebSocket
echo "🐍 Creando servidor WebSocket..."
cat << 'EOF' > /usr/local/bin/ssh-ws.py
import socket, threading, select

# Configuración
LISTEN_PORT = 80
SSH_HOST = "127.0.0.1"
SSH_PORT = 22
PASS_RESPONSE = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"

def bridge(client, remote):
    sockets = [client, remote]
    try:
        while True:
            read_sockets, _, _ = select.select(sockets, [], [])
            for sock in read_sockets:
                data = sock.recv(8192)
                if not data:
                    return
                if sock is client:
                    remote.sendall(data)
                else:
                    client.sendall(data)
    except:
        pass
    finally:
        client.close()
        remote.close()

def handle_client(client_sock, addr):
    try:
        # Leer el header HTTP del Injector
        request = client_sock.recv(8192).decode('utf-8', errors='ignore')
        
        # Si es un WebSocket Upgrade, respondemos con el handshake
        if "Upgrade: websocket" in request or "GET /" in request:
            client_sock.sendall(PASS_RESPONSE.encode())
            
            # Conectar al SSH local
            ssh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssh_sock.connect((SSH_HOST, SSH_PORT))
            
            # Iniciar el puente
            bridge(client_sock, ssh_sock)
    except:
        client_sock.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(100)
    print(f"[*] WebSocket escuchando en el puerto {LISTEN_PORT}")

    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()

if __name__ == "__main__":
    main()
EOF

chmod +x /usr/local/bin/ssh-ws.py

# 3. Crear Servicio Systemd
echo "🔄 Creando servicio persistente..."
cat << EOF > /etc/systemd/system/ssh-ws.service
[Unit]
Description=SSH WebSocket Tunnel
After=network.target

[Service]
ExecStartPre=-/usr/bin/fuser -k 80/tcp
ExecStart=/usr/bin/python3 /usr/local/bin/ssh-ws.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

# 4. Activar todo
ufw allow 80/tcp
systemctl daemon-reload
systemctl enable ssh-ws
systemctl restart ssh-ws

echo "---"
echo "✅ ¡WEBSOCKET ONLINE!"
echo "📍 Puerto: 80"
echo "📖 En HTTP Injector usa el método: SSH -> HTTP Proxy -> Custom Payload"
echo "📖 Payload sugerido: GET / HTTP/1.1[crlf]Host: tu_dominio.com[crlf]Upgrade: websocket[crlf][crlf]"
