#!/bin/bash

if [ "$EUID" -ne 0 ]; then 
  echo "❌ Por favor, ejecuta con sudo"
  exit
fi

echo "🌐 Configurando Túnel HTTP para Injector..."

# 1. Configurar SSH para máxima compatibilidad
echo "🔧 Ajustando parámetros de SSH..."
sed -i '/HostKeyAlgorithms/d' /etc/ssh/sshd_config
sed -i '/PubkeyAcceptedAlgorithms/d' /etc/ssh/sshd_config
cat << EOF >> /etc/ssh/sshd_config
HostKeyAlgorithms +ssh-rsa,ssh-ed25519
PubkeyAcceptedAlgorithms +ssh-rsa,ssh-ed25519
EOF
systemctl restart ssh

# 2. Crear el script de Python para el Túnel HTTP
echo "🐍 Creando servidor de respuesta HTTP..."
cat << 'EOF' > /usr/local/bin/ssh-http.py
import socket, threading, select

# Configuración del servidor
PORT = 8080  # Puedes cambiarlo a 80 si prefieres
SSH_ADDR = ("127.0.0.1", 22)
RESPONSE = "HTTP/1.1 200 Connection Established\r\n\r\n"

def bridge(c1, c2):
    try:
        while True:
            r, w, e = select.select([c1, c2], [], [])
            if c1 in r:
                data = c1.recv(8192)
                if not data: break
                c2.sendall(data)
            if c2 in r:
                data = c2.recv(8192)
                if not data: break
                c1.sendall(data)
    except: pass
    finally:
        c1.close(); c2.close()

def handle(client_conn, addr):
    try:
        # Recibir el Payload del cliente
        payload = client_conn.recv(8192).decode('utf-8', errors='ignore')
        
        # Si el cliente envía algo (CONNECT o GET), respondemos éxito
        if len(payload) > 0:
            client_conn.sendall(RESPONSE.encode())
            
            # Conectar al SSH
            ssh_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssh_conn.connect(SSH_ADDR)
            
            # Unir las dos conexiones
            bridge(client_conn, ssh_conn)
    except:
        client_conn.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(100)
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
EOF

chmod +x /usr/local/bin/ssh-http.py

# 3. Crear el servicio persistente
echo "🔄 Creando servicio en systemd..."
cat << EOF > /etc/systemd/system/ssh-http.service
[Unit]
Description=SSH HTTP Tunnel
After=network.target

[Service]
ExecStartPre=-/usr/bin/fuser -k 8080/tcp
ExecStart=/usr/bin/python3 /usr/local/bin/ssh-http.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

# 4. Firewall y Arranque
ufw allow 8080/tcp
systemctl daemon-reload
systemctl enable ssh-http
systemctl restart ssh-http

echo "---"
echo "✅ ¡SERVIDOR HTTP ONLINE!"
echo "📍 Puerto: 8080"
echo "📖 Configuración en Injector:"
echo "   - Método: SSH -> HTTP Proxy -> Custom Payload"
echo "   - Proxy IP: IP_DE_TU_VPS"
echo "   - Proxy Puerto: 8080"
echo "   - Payload ejemplo: CONNECT [host_port] [protocol][crlf][crlf]"
