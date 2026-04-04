"""SSH service — connects to a VPS via paramiko and manages VPNPro users.

All username inputs are validated with a strict regex before any shell
command to prevent command-injection attacks.
Passwords are set via chpasswd stdin (never interpolated in the shell).
Password files on the VPS are written with SFTP (no shell involved).
"""

from __future__ import annotations

import io
import re
import stat
from datetime import datetime, timedelta
from typing import Any

import paramiko

# Compatible con cuentas creadas por scripts Bash (legacy y nuevas).
# Permite letras, numeros, guion, guion bajo y punto.
_USERNAME_RE = re.compile(r'^[A-Za-z0-9._-]{1,32}$')


class SSHService:
    def __init__(self, server) -> None:
        self._server = server
        self._client: paramiko.SSHClient | None = None

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    def connect(self) -> tuple[bool, str]:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=self._server.ip,
                port=self._server.port,
                username=self._server.ssh_user,
                password=self._server.get_ssh_password(),
                timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )
            self._client = client
            return True, 'ok'
        except Exception as exc:
            return False, str(exc)

    def disconnect(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    def _run(self, cmd: str, timeout: int = 30) -> tuple[bool, str, str]:
        """Execute *cmd* and return (success, stdout, stderr)."""
        assert self._client is not None
        try:
            _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode('utf-8', errors='replace').strip()
            err = stderr.read().decode('utf-8', errors='replace').strip()
            code = stdout.channel.recv_exit_status()
            return code == 0, out, err
        except Exception as exc:
            return False, '', str(exc)

    def _sftp_write(self, remote_path: str, content: str) -> None:
        """Write *content* to *remote_path* via SFTP (no shell)."""
        assert self._client is not None
        sftp = self._client.open_sftp()
        try:
            with sftp.open(remote_path, 'w') as fh:
                fh.write(content)
            sftp.chmod(remote_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        finally:
            sftp.close()

    def _sftp_read(self, remote_path: str, default: str = '') -> str:
        assert self._client is not None
        sftp = self._client.open_sftp()
        try:
            with sftp.open(remote_path, 'r') as fh:
                return fh.read().decode('utf-8', errors='replace')
        except FileNotFoundError:
            return default
        finally:
            sftp.close()

    def _sftp_remove(self, remote_path: str) -> None:
        assert self._client is not None
        sftp = self._client.open_sftp()
        try:
            sftp.remove(remote_path)
        except FileNotFoundError:
            pass
        finally:
            sftp.close()

    def _set_password_stdin(self, username: str, password: str) -> tuple[bool, str]:
        """Set system password using chpasswd via stdin (injection-safe)."""
        assert self._client is not None
        try:
            stdin, stdout, stderr = self._client.exec_command('chpasswd', timeout=15)
            stdin.write(f'{username}:{password}\n'.encode())
            stdin.flush()
            stdin.channel.shutdown_write()
            err = stderr.read().decode('utf-8', errors='replace').strip()
            code = stdout.channel.recv_exit_status()
            return code == 0, err
        except Exception as exc:
            return False, str(exc)

    def _valid_port(self, port: int) -> bool:
        return isinstance(port, int) and 1 <= port <= 65535

    def _reload_enable_restart_service(self, service_name: str) -> tuple[bool, str]:
        ok, _, err = self._run(
            f'systemctl daemon-reload && systemctl enable {service_name} && systemctl restart {service_name}'
        )
        if not ok:
            return False, err or f'No se pudo reiniciar el servicio {service_name}'
        return True, 'ok'

    def _free_tcp_port(self, port: int) -> tuple[bool, str]:
        cmd = (
            f"if command -v fuser >/dev/null 2>&1; then "
            f"  fuser -k {port}/tcp >/dev/null 2>&1 || true; "
            f"else "
            f"  pids=$(ss -lntp 2>/dev/null | awk '/:{port} / {{print $NF}}' | sed -n 's/.*pid=\\([0-9]\\+\\).*/\\1/p' | sort -u); "
            f"  for pid in $pids; do kill -9 \"$pid\" >/dev/null 2>&1 || true; done; "
            f"fi"
        )
        ok, _, err = self._run(cmd)
        if not ok:
            return False, err or f'No se pudo liberar el puerto {port}/tcp'
        return True, 'ok'

    def _free_udp_port(self, port: int) -> tuple[bool, str]:
        cmd = (
            f"if command -v fuser >/dev/null 2>&1; then "
            f"  fuser -k {port}/udp >/dev/null 2>&1 || true; "
            f"else "
            f"  pids=$(ss -lnup 2>/dev/null | awk '/:{port} / {{print $NF}}' | sed -n 's/.*pid=\\([0-9]\\+\\).*/\\1/p' | sort -u); "
            f"  for pid in $pids; do kill -9 \"$pid\" >/dev/null 2>&1 || true; done; "
            f"fi"
        )
        ok, _, err = self._run(cmd)
        if not ok:
            return False, err or f'No se pudo liberar el puerto {port}/udp'
        return True, 'ok'

    def _verify_service_listener(self, service_name: str, port: int, proto: str = 'tcp') -> tuple[bool, str]:
        if proto == 'udp':
            port_check = (
                f"(command -v ss >/dev/null 2>&1 && ss -lnup 2>/dev/null | grep -qE ':{port}\\b') "
                f"|| (command -v netstat >/dev/null 2>&1 && netstat -lnup 2>/dev/null | grep -qE ':{port}[[:space:]]')"
            )
        else:
            port_check = (
                f"(command -v ss >/dev/null 2>&1 && ss -lntp 2>/dev/null | grep -qE ':{port}\\b') "
                f"|| (command -v netstat >/dev/null 2>&1 && netstat -lntp 2>/dev/null | grep -qE ':{port}[[:space:]]')"
            )

        cmd = (
            f"systemctl daemon-reload && systemctl enable {service_name} >/dev/null 2>&1 && systemctl restart {service_name} >/dev/null 2>&1; "
            f"for _ in 1 2 3 4 5; do "
            f"  systemctl is-active --quiet {service_name} && {port_check} && exit 0; "
            f"  sleep 1; "
            f"done; "
            f"echo '--- STATUS ---'; systemctl --no-pager --full status {service_name} 2>&1 | tail -n 20; "
            f"echo '--- JOURNAL ---'; journalctl -u {service_name} -n 20 --no-pager 2>&1 | tail -n 20; "
            f"exit 1"
        )
        ok, out, err = self._run(cmd)
        if ok:
            return True, 'ok'
        detail = '\n'.join(part for part in [out, err] if part).strip()
        return False, detail or f'El servicio {service_name} no quedo activo o no abrio el puerto {port}/{proto}'

    def _service_has_listener(self, service_name: str, port: int | None, proto: str = 'tcp') -> bool:
        if not port:
            return False

        if proto == 'udp':
            port_check = (
                f"(command -v ss >/dev/null 2>&1 && ss -lnup 2>/dev/null | grep -qE ':{port}\\b') "
                f"|| (command -v netstat >/dev/null 2>&1 && netstat -lnup 2>/dev/null | grep -qE ':{port}[[:space:]]')"
            )
        else:
            port_check = (
                f"(command -v ss >/dev/null 2>&1 && ss -lntp 2>/dev/null | grep -qE ':{port}\\b') "
                f"|| (command -v netstat >/dev/null 2>&1 && netstat -lntp 2>/dev/null | grep -qE ':{port}[[:space:]]')"
            )

        ok, _, _ = self._run(
            f"systemctl is-active --quiet {service_name} && ({port_check})"
        )
        return bool(ok)

    def _read_service_port(self, service_name: str, port_cmd: str) -> int | None:
        _, port_out, _ = self._run(port_cmd)
        port_value = (port_out or '').strip()
        return int(port_value) if port_value.isdigit() else None

    def _ensure_ssh_injector_compat(self) -> tuple[bool, str]:
        cmd = (
            "sed -i '/HostKeyAlgorithms +ssh-rsa,ssh-ed25519/d' /etc/ssh/sshd_config "
            "&& sed -i '/PubkeyAcceptedAlgorithms +ssh-rsa,ssh-ed25519/d' /etc/ssh/sshd_config "
            "&& sed -i '/^PasswordAuthentication /d' /etc/ssh/sshd_config "
            "&& sed -i '/^PermitTunnel /d' /etc/ssh/sshd_config "
            "&& printf '\nHostKeyAlgorithms +ssh-rsa,ssh-ed25519\nPubkeyAcceptedAlgorithms +ssh-rsa,ssh-ed25519\n' >> /etc/ssh/sshd_config "
            "&& printf 'PasswordAuthentication yes\nPermitTunnel yes\n' >> /etc/ssh/sshd_config "
            "&& (systemctl restart ssh || service ssh restart || true)"
        )
        ok, _, err = self._run(cmd)
        if not ok:
            return False, err or 'No se pudo ajustar compatibilidad SSH'
        return True, 'ok'

    def _allow_firewall_port(self, port: int, proto: str = 'tcp') -> None:
        self._run(
            f'if command -v ufw >/dev/null 2>&1; then ufw allow {port}/{proto} >/dev/null 2>&1; fi'
        )

    def open_port_rules(self, port: int, protocols: list[str]) -> tuple[bool, str]:
        if not self._valid_port(port):
            return False, 'Puerto invalido (1-65535).'
        if not protocols:
            return False, 'Debes indicar al menos un protocolo (tcp/udp).'

        normalized = []
        for proto in protocols:
            p = (proto or '').strip().lower()
            if p in {'tcp', 'udp'} and p not in normalized:
                normalized.append(p)

        if not normalized:
            return False, 'Protocolos invalidos. Usa tcp y/o udp.'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            # UFW + iptables fallback para maximizar compatibilidad.
            for proto in normalized:
                ok2, _, err = self._run(
                    f"if command -v ufw >/dev/null 2>&1; then ufw allow {port}/{proto} >/dev/null 2>&1 || true; fi; "
                    f"if command -v iptables >/dev/null 2>&1; then "
                    f"  iptables -C INPUT -p {proto} --dport {port} -j ACCEPT >/dev/null 2>&1 || "
                    f"  iptables -I INPUT -p {proto} --dport {port} -j ACCEPT >/dev/null 2>&1 || true; "
                    f"fi"
                )
                if not ok2:
                    return False, err or f'No se pudo abrir {port}/{proto} en firewall'

            return True, f'Puerto {port} abierto en firewall ({"/".join(normalized)}).'
        finally:
            self.disconnect()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def test_connection(self) -> tuple[bool, str]:
        ok, msg = self.connect()
        if ok:
            self.disconnect()
        return ok, msg

    def reboot_server(self) -> tuple[bool, str]:
        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            ok2, _, err = self._run(
                "nohup sh -c 'sleep 2; /sbin/reboot || reboot' >/dev/null 2>&1 &"
            )
            if not ok2:
                return False, err or 'No se pudo enviar la orden de reinicio'
            return True, 'Orden de reinicio enviada al VPS'
        finally:
            self.disconnect()

    def install_checkuser(self, port: int = 2052) -> tuple[bool, str]:
        if not self._valid_port(port):
            return False, 'Puerto invalido (1-65535).'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            ok2, _, err = self._run(
                'export DEBIAN_FRONTEND=noninteractive; '
                'apt-get update -y >/dev/null 2>&1 && '
                'apt-get install -y git python3 python3-pip python3-venv >/dev/null 2>&1',
                timeout=240,
            )
            if not ok2:
                return False, err or 'No se pudieron instalar dependencias para CheckUser'

            cmd = f"""
set -e
VENV_PATH="/opt/checkuser_venv"
WORKDIR="/opt/DTCheckUser"
LOGFILE="/tmp/checkuser-install.log"

rm -f "$LOGFILE"
touch "$LOGFILE"

if [ -d "$WORKDIR/.git" ]; then
    if ! git -C "$WORKDIR" pull --ff-only >>"$LOGFILE" 2>&1; then
        rm -rf "$WORKDIR"
    fi
fi

if [ ! -d "$WORKDIR/.git" ]; then
    rm -rf "$WORKDIR"
    if ! git clone --depth 1 https://github.com/DiegoPintoTeam/DTCheckUser.git "$WORKDIR" >>"$LOGFILE" 2>&1; then
        echo 'No se pudo clonar DTCheckUser.'
        tail -n 80 "$LOGFILE"
        exit 31
    fi
fi

if [ ! -f "$WORKDIR/requirements.txt" ]; then
    echo 'No se pudo clonar DTCheckUser.'
    tail -n 80 "$LOGFILE"
    exit 38
fi

if ! python3 -m venv "$VENV_PATH" >>"$LOGFILE" 2>&1; then
    echo 'No se pudo crear el entorno virtual de CheckUser.'
    tail -n 80 "$LOGFILE"
    exit 32
fi

"$VENV_PATH/bin/pip" install --upgrade pip setuptools wheel >>"$LOGFILE" 2>&1 || true
if ! "$VENV_PATH/bin/pip" install -r "$WORKDIR/requirements.txt" >>"$LOGFILE" 2>&1; then
    echo 'Fallo al instalar requirements de CheckUser.'
    tail -n 80 "$LOGFILE"
    exit 33
fi

if [ ! -f "$WORKDIR/checkuser/__main__.py" ]; then
    echo 'Repositorio DTCheckUser no contiene checkuser/__main__.py.'
    tail -n 80 "$LOGFILE"
    exit 34
fi

if ! PYTHONPATH="$WORKDIR" "$VENV_PATH/bin/python3" -m checkuser --help >>"$LOGFILE" 2>&1; then
    echo 'No se pudo ejecutar python -m checkuser --help.'
    tail -n 80 "$LOGFILE"
    exit 35
fi

cat <<'EOF' >/etc/systemd/system/checkuser.service
[Unit]
Description=CheckUser Service
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Environment=PYTHONPATH=/opt/DTCheckUser
WorkingDirectory=/opt/DTCheckUser
ExecStart=/opt/checkuser_venv/bin/python3 -m checkuser --port {port} --start
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable checkuser.service >/dev/null 2>&1
if ! systemctl restart checkuser.service; then
    echo '--- STATUS ---'
    systemctl --no-pager --full status checkuser.service 2>&1 | tail -n 40
    echo '--- JOURNAL ---'
    journalctl -u checkuser.service -n 40 --no-pager 2>&1 | tail -n 40
    echo '--- INSTALL LOG ---'
    tail -n 40 "$LOGFILE"
    exit 36
fi

if ! systemctl is-active --quiet checkuser.service; then
    echo '--- STATUS ---'
    systemctl --no-pager --full status checkuser.service 2>&1 | tail -n 40
    echo '--- JOURNAL ---'
    journalctl -u checkuser.service -n 40 --no-pager 2>&1 | tail -n 40
    echo '--- INSTALL LOG ---'
    tail -n 40 "$LOGFILE"
    exit 37
fi

rm -f "$LOGFILE"
"""
            ok2, out, err = self._run(cmd, timeout=300)
            if not ok2:
                detail = '\n'.join(part for part in [out, err] if part).strip()
                return False, detail or 'No se pudo instalar/iniciar CheckUser en el VPS'

            self._allow_firewall_port(port, 'tcp')
            return True, f'CheckUser instalado y activo en el puerto {port}/tcp.'
        finally:
            self.disconnect()

    def uninstall_checkuser(self) -> tuple[bool, str]:
        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            cmd = """
set -e
systemctl disable --now checkuser.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/checkuser.service
systemctl daemon-reload
rm -rf /opt/checkuser_venv
rm -rf /opt/DTCheckUser
rm -rf /tmp/vpnpro-checkuser
"""
            ok2, out, err = self._run(cmd, timeout=120)
            if not ok2:
                detail = '\n'.join(part for part in [out, err] if part).strip()
                return False, detail or 'No se pudo desinstalar CheckUser en el VPS'
            return True, 'CheckUser desinstalado del VPS.'
        finally:
            self.disconnect()

    def setup_http_custom_tunnel(self, port: int = 8080) -> tuple[bool, str]:
        if not self._valid_port(port):
            return False, 'Puerto invalido (1-65535).'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            ok2, err = self._ensure_ssh_injector_compat()
            if not ok2:
                return False, err

            ok2, err = self._free_tcp_port(port)
            if not ok2:
                return False, err

            script = f'''#!/usr/bin/env python3
import socket
import threading
import select

LISTEN_PORT = {port}
SSH_ADDR = ("127.0.0.1", 22)
RESPONSE = "HTTP/1.1 200 Connection Established\\r\\n\\r\\n"


def bridge(c1, c2):
    try:
        while True:
            ready, _, _ = select.select([c1, c2], [], [])
            if c1 in ready:
                data = c1.recv(8192)
                if not data:
                    break
                c2.sendall(data)
            if c2 in ready:
                data = c2.recv(8192)
                if not data:
                    break
                c1.sendall(data)
    finally:
        c1.close()
        c2.close()


def handle(client_conn):
    try:
        payload = client_conn.recv(8192)
        if payload:
            client_conn.sendall(RESPONSE.encode())
            ssh_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssh_conn.connect(SSH_ADDR)
            bridge(client_conn, ssh_conn)
    except Exception:
        client_conn.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(100)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
'''
            self._sftp_write('/usr/local/bin/ssh-http.py', script)
            self._run('chmod 755 /usr/local/bin/ssh-http.py')

            service = f'''[Unit]
Description=SSH HTTP Tunnel
After=network.target

[Service]
Type=simple
ExecStartPre=-/usr/bin/fuser -k {port}/tcp
ExecStart=/usr/bin/python3 /usr/local/bin/ssh-http.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
'''
            self._sftp_write('/etc/systemd/system/ssh-http.service', service)
            ok2, err = self._verify_service_listener('ssh-http.service', port, 'tcp')
            if not ok2:
                return False, err

            self._allow_firewall_port(port, 'tcp')
            return True, f'HTTP activo en el puerto {port}/tcp.'
        finally:
            self.disconnect()

    def setup_ssl_tunnel(self, port: int = 443) -> tuple[bool, str]:
        if not self._valid_port(port):
            return False, 'Puerto invalido (1-65535).'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            ok2, err = self._ensure_ssh_injector_compat()
            if not ok2:
                return False, err

            ok2, err = self._free_tcp_port(port)
            if not ok2:
                return False, err

            ok2, _, err = self._run(
                "mkdir -p /etc/ssh-ssl && "
                "openssl req -x509 -nodes -days 365 -newkey rsa:2048 "
                "-keyout /etc/ssh-ssl/selfsigned.key "
                "-out /etc/ssh-ssl/selfsigned.crt "
                "-subj '/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost'"
            )
            if not ok2:
                return False, err or 'No se pudieron generar certificados SSL'

            script = f'''#!/usr/bin/env python3
import socket
import threading
import ssl

LISTEN_PORT = {port}


def tunnel(s1, s2):
    try:
        while True:
            data = s1.recv(8192)
            if not data:
                break
            s2.sendall(data)
    finally:
        try:
            s1.close()
        except Exception:
            pass
        try:
            s2.close()
        except Exception:
            pass


def handle_ssl(client):
    try:
        ssh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssh_sock.connect(("127.0.0.1", 22))
        t1 = threading.Thread(target=tunnel, args=(client, ssh_sock), daemon=True)
        t2 = threading.Thread(target=tunnel, args=(ssh_sock, client), daemon=True)
        t1.start()
        t2.start()
    except Exception:
        client.close()


def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile="/etc/ssh-ssl/selfsigned.crt",
        keyfile="/etc/ssh-ssl/selfsigned.key",
    )
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(100)

    with context.wrap_socket(server, server_side=True) as ssock:
        while True:
            try:
                conn, _ = ssock.accept()
                threading.Thread(target=handle_ssl, args=(conn,), daemon=True).start()
            except Exception:
                continue


if __name__ == "__main__":
    main()
'''
            self._sftp_write('/usr/local/bin/ssh-ssl.py', script)
            self._run('chmod 755 /usr/local/bin/ssh-ssl.py')

            service = f'''[Unit]
Description=SSH SSL Tunnel
After=network.target

[Service]
Type=simple
ExecStartPre=-/usr/bin/fuser -k {port}/tcp
ExecStart=/usr/bin/python3 /usr/local/bin/ssh-ssl.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
'''
            self._sftp_write('/etc/systemd/system/ssh-ssl.service', service)
            ok2, err = self._verify_service_listener('ssh-ssl.service', port, 'tcp')
            if not ok2:
                return False, err

            self._allow_firewall_port(port, 'tcp')
            self._allow_firewall_port(22, 'tcp')
            return True, f'SSL Tunnel activo en el puerto {port}/tcp.'
        finally:
            self.disconnect()

    def setup_websocket_tunnel(self, port: int = 80) -> tuple[bool, str]:
        if not self._valid_port(port):
            return False, 'Puerto invalido (1-65535).'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            ok2, err = self._ensure_ssh_injector_compat()
            if not ok2:
                return False, err

            ok2, _, err = self._run('apt-get install -y python3 iproute2 psmisc >/dev/null 2>&1 || true')
            if not ok2:
                return False, err or 'No se pudieron asegurar dependencias para WebSocket Tunnel'

            ok2, err = self._free_tcp_port(port)
            if not ok2:
                return False, err

            script = f'''#!/usr/bin/env python3
import socket
import threading
import select

LISTEN_PORT = {port}
PASS_RESPONSE = (
    "HTTP/1.1 101 Switching Protocols\\r\\n"
    "Upgrade: websocket\\r\\n"
    "Connection: Upgrade\\r\\n\\r\\n"
)


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
    finally:
        client.close()
        remote.close()


def handle_client(client_sock):
    try:
        request = client_sock.recv(8192).decode('utf-8', errors='ignore')
        if "Upgrade: websocket" in request or "GET /" in request:
            client_sock.sendall(PASS_RESPONSE.encode())
            ssh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssh_sock.connect(("127.0.0.1", 22))
            bridge(client_sock, ssh_sock)
    except Exception:
        client_sock.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(100)
    while True:
        client, _ = server.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
'''
            self._sftp_write('/usr/local/bin/ssh-ws.py', script)
            self._run('chmod 755 /usr/local/bin/ssh-ws.py')

            service = f'''[Unit]
Description=SSH WebSocket Tunnel
After=network.target

[Service]
Type=simple
ExecStartPre=-/usr/bin/fuser -k {port}/tcp
ExecStart=/usr/bin/python3 /usr/local/bin/ssh-ws.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
'''
            self._sftp_write('/etc/systemd/system/ssh-ws.service', service)
            ok2, err = self._verify_service_listener('ssh-ws.service', port, 'tcp')
            if not ok2:
                return False, f'WebSocket Tunnel fallo al iniciar en {port}/tcp. {err}'

            self._allow_firewall_port(port, 'tcp')
            return True, f'WebSocket Tunnel activo en el puerto {port}/tcp.'
        finally:
            self.disconnect()

    def setup_badvpn_udpgw(self, port: int = 7300) -> tuple[bool, str]:
        if not self._valid_port(port):
            return False, 'Puerto invalido (1-65535).'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            # Detener procesos badvpn previos (ANTES de descargar)
            # Best-effort: no importa si el servicio no existe todavía
            self._run(
                'systemctl disable --now badvpn.service >/dev/null 2>&1; '
                'pkill -9 -f badvpn-udpgw >/dev/null 2>&1; '
                'sleep 1; '
                'rm -f /usr/bin/badvpn-udpgw >/dev/null 2>&1; '
                'sleep 1; '
                'true'
            )

            # Descargar binario precompilado
            ok2, _, err = self._run(
                'wget https://github.com/DiegoPintoTeam/VPNPro/raw/main/Install/badvpn-udpgw '
                '-O /usr/bin/badvpn-udpgw && chmod +x /usr/bin/badvpn-udpgw'
            )
            if not ok2:
                return False, err or 'No se pudo descargar badvpn-udpgw'

            # Verificar que el binario esté disponible
            ok2, _, err = self._run('[ -x /usr/bin/badvpn-udpgw ]')
            if not ok2:
                return False, 'badvpn-udpgw no está disponible en /usr/bin'

            # Crear y habilitar el servicio sistemd (exacto como funciona en el VPS)
            ok2, _, err = self._run(
                'echo -e "[Unit]\\nDescription=BadVPN UDP Gateway\\n'
                'After=network.target\\n\\n[Service]\\nType=simple\\n'
                'ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000\\n'
                'Restart=always\\n\\n[Install]\\nWantedBy=multi-user.target" > /etc/systemd/system/badvpn.service && '
                'systemctl daemon-reload && systemctl enable badvpn && systemctl start badvpn'
            )
            if not ok2:
                return False, err or 'No se pudo crear/iniciar servicio BadVPN'

            # Verificar que el servicio está activo
            ok2, _, err = self._run('systemctl is-active --quiet badvpn.service')
            if not ok2:
                return False, err or 'Servicio badvpn no está activo. Verifica con: systemctl status badvpn'

            return True, 'BadVPN UDPGW activo en el puerto 7300.'
        finally:
            self.disconnect()

    def disable_badvpn_udpgw(self) -> tuple[bool, str]:
        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            self._run('systemctl disable --now badvpn.service >/dev/null 2>&1 || true')
            self._run('rm -f /etc/systemd/system/badvpn.service')
            self._run('systemctl daemon-reload')
            return True, 'BadVPN desactivado.'
        finally:
            self.disconnect()

    def get_port_modules_details(self) -> tuple[bool, dict[str, dict[str, Any]], str]:
        ok, msg = self.connect()
        if not ok:
            return False, {}, f'No se pudo conectar: {msg}'
        try:
            modules = {
                'http_custom': {
                    'service': 'ssh-http.service',
                    'label': 'HTTP',
                    'proto': 'tcp',
                    'listener_proto': 'tcp',
                    'port_cmd': "grep -oE 'ExecStartPre=-/usr/bin/fuser -k [0-9]+/tcp' /etc/systemd/system/ssh-http.service 2>/dev/null | grep -oE '[0-9]+' | head -n1",
                },
                'ssl_tunnel': {
                    'service': 'ssh-ssl.service',
                    'label': 'SSL Tunnel',
                    'proto': 'tcp',
                    'listener_proto': 'tcp',
                    'port_cmd': "grep -oE 'ExecStartPre=-/usr/bin/fuser -k [0-9]+/tcp' /etc/systemd/system/ssh-ssl.service 2>/dev/null | grep -oE '[0-9]+' | head -n1",
                },
                'websocket_tunnel': {
                    'service': 'ssh-ws.service',
                    'label': 'WebSocket Tunnel',
                    'proto': 'tcp',
                    'listener_proto': 'tcp',
                    'port_cmd': "grep -oE 'ExecStartPre=-/usr/bin/fuser -k [0-9]+/tcp' /etc/systemd/system/ssh-ws.service 2>/dev/null | grep -oE '[0-9]+' | head -n1",
                },
                'badvpn_udp': {
                    'service': 'badvpn.service',
                    'label': 'BadVPN UDPGW',
                    'proto': 'udp',
                    'listener_proto': 'udp',
                    'port': 7300,
                },
                'checkuser': {
                    'service': 'checkuser.service',
                    'label': 'CheckUser',
                    'proto': 'tcp',
                    'listener_proto': 'tcp',
                    'port_cmd': "sed -n 's/.*--port \\([0-9]\\+\\).*/\\1/p' /etc/systemd/system/checkuser.service 2>/dev/null | head -n1",
                },
            }

            details: dict[str, dict[str, Any]] = {}
            for key, meta in modules.items():
                # BadVPN usa puerto fijo y detección solo por servicio (UDP localhost no es fiable con ss)
                if 'port' in meta:
                    port_value = str(meta['port'])
                    ok_svc, _, _ = self._run(f'systemctl is-active --quiet {meta["service"]}')
                    is_active = bool(ok_svc)
                else:
                    _, port_out, _ = self._run(meta['port_cmd'])
                    port_value = (port_out or '').strip()
                    port_int = int(port_value) if port_value.isdigit() else None
                    is_active = self._service_has_listener(meta['service'], port_int, meta['listener_proto'])
                details[key] = {
                    'label': meta['label'],
                    'active': is_active,
                    'port': port_value or '-',
                    'proto': meta['proto'],
                }

            return True, details, ''
        finally:
            self.disconnect()

    def get_port_modules_status(self) -> tuple[bool, dict[str, bool], str]:
        ok, msg = self.connect()
        if not ok:
            return False, {}, f'No se pudo conectar: {msg}'
        try:
            mapping = {
                'http_custom': {
                    'service': 'ssh-http.service',
                    'port_cmd': "grep -oE 'ExecStartPre=-/usr/bin/fuser -k [0-9]+/tcp' /etc/systemd/system/ssh-http.service 2>/dev/null | grep -oE '[0-9]+' | head -n1",
                    'proto': 'tcp',
                },
                'ssl_tunnel': {
                    'service': 'ssh-ssl.service',
                    'port_cmd': "grep -oE 'ExecStartPre=-/usr/bin/fuser -k [0-9]+/tcp' /etc/systemd/system/ssh-ssl.service 2>/dev/null | grep -oE '[0-9]+' | head -n1",
                    'proto': 'tcp',
                },
                'websocket_tunnel': {
                    'service': 'ssh-ws.service',
                    'port_cmd': "grep -oE 'ExecStartPre=-/usr/bin/fuser -k [0-9]+/tcp' /etc/systemd/system/ssh-ws.service 2>/dev/null | grep -oE '[0-9]+' | head -n1",
                    'proto': 'tcp',
                },
                'badvpn_udp': {
                    'service': 'badvpn.service',
                    'port': 7300,
                    'proto': 'udp',
                },
                'checkuser': {
                    'service': 'checkuser.service',
                    'port_cmd': "sed -n 's/.*--port \\([0-9]\\+\\).*/\\1/p' /etc/systemd/system/checkuser.service 2>/dev/null | head -n1",
                    'proto': 'tcp',
                },
            }
            status: dict[str, bool] = {}
            for key, meta in mapping.items():
                if 'port' in meta:
                    # BadVPN: detección solo por servicio activo (UDP localhost no es fiable con ss)
                    ok_svc, _, _ = self._run(f'systemctl is-active --quiet {meta["service"]}')
                    status[key] = bool(ok_svc)
                else:
                    port_value = self._read_service_port(meta['service'], meta['port_cmd'])
                    status[key] = self._service_has_listener(meta['service'], port_value, meta['proto'])
            return True, status, ''
        finally:
            self.disconnect()

    def get_server_info(self) -> tuple[bool, dict[str, Any], str]:
        ok, msg = self.connect()
        if not ok:
            return False, {}, msg
        try:
            info: dict[str, Any] = {}
            ok2, out, _ = self._run("who | awk '{print $1}' | sort -u | wc -l")
            if not ok2:
                ok2, out, _ = self._run(
                    "ps aux | grep 'sshd:' | grep -v grep | "
                    "awk '{print $1}' | grep -v root | sort -u | wc -l"
                )
            info['online'] = out if ok2 else '0'

            ok2, out, _ = self._run(
                "wc -l < /root/usuarios.db 2>/dev/null || echo 0"
            )
            info['total_users'] = out.strip() if ok2 else '0'

            ok2, out, _ = self._run(
                "free -m | awk 'NR==2{printf \"%s / %s MB  (%.0f%%)\", $3,$2,$3*100/$2}'"
            )
            info['ram'] = out if ok2 else 'N/A'

            ok2, out, _ = self._run(
                "df -h / | awk 'NR==2{printf \"%s / %s (%s)\", $3,$2,$5}'"
            )
            info['disk'] = out if ok2 else 'N/A'

            ok2, out, _ = self._run(
                "grep '^cpu ' /proc/stat | "
                "awk '{u=$2+$4; t=$2+$4+$5; if (t>0) printf \"%.1f%%\", (u*100/t); else print \"0.0%\"}'"
            )
            info['cpu'] = out if ok2 else 'N/A'

            ok2, out, _ = self._run("uptime -p 2>/dev/null || uptime")
            info['uptime'] = out if ok2 else 'N/A'

            ok2, out, _ = self._run(
                "grep PRETTY_NAME /etc/os-release 2>/dev/null | "
                "cut -d= -f2 | tr -d '\"'"
            )
            info['os'] = out if ok2 else 'Linux'

            return True, info, ''
        finally:
            self.disconnect()

    def get_online_users(self) -> tuple[bool, dict[str, int], str]:
        ok, msg = self.connect()
        if not ok:
            return False, {}, msg
        try:
            online: dict[str, int] = {}

            # On this server format, active sessions appear as:
            #   sshd: NOMBRE-APELLIDO   (no @, no [priv], no [net])
            # Filter out auxiliary sshd processes and count unique names.
            ok2, out, _ = self._run(
                "ps -eo args= | grep 'sshd: '"
                " | grep -v '\\['"
                " | grep -v '@'"
                " | grep -v '/usr/sbin/sshd'"
                " | grep -v 'grep'"
                " | sed 's/.*sshd: //'"
                " | sort | uniq -c"
            )
            if ok2 and out.strip():
                for line in out.splitlines():
                    parts = line.strip().split(None, 1)
                    if len(parts) == 2:
                        try:
                            count = int(parts[0])
                            user = parts[1].strip().upper()
                            if user and user != 'ROOT':
                                online[user] = count
                        except ValueError:
                            pass

            return True, online, ''
        finally:
            self.disconnect()

    def debug_online_raw(self) -> tuple[bool, dict, str]:
        """Return raw output from multiple detection methods for diagnostics."""
        ok, msg = self.connect()
        if not ok:
            return False, {}, msg
        try:
            result: dict = {}

            _, out, _ = self._run("ps aux | grep sshd | grep -v grep")
            result['ps_sshd'] = out

            _, out, _ = self._run(
                "ps -eo args= | grep -oE 'sshd: [^[:space:]@]+@[^[:space:]]+' || true"
            )
            result['sshd_at_sessions'] = out

            _, out, _ = self._run("who")
            result['who'] = out

            _, out, _ = self._run("w | tail -n +3 | awk '{print $1}'")
            result['w_users'] = out

            _, out, _ = self._run(
                "ss -tnp state established | grep sshd | awk '{print $NF}' | grep -oP 'pid=\\K[0-9]+'"
                " | xargs -I{} cat /proc/{}/status 2>/dev/null | grep '^Name\\|^Pid' || true"
            )
            result['ss_sshd_pids'] = out

            return True, result, ''
        finally:
            self.disconnect()

    def list_users_for_sync(self) -> tuple[bool, list[dict[str, Any]], str]:
        """Read current VPS users from /root/usuarios.db for panel synchronization."""
        ok, msg = self.connect()
        if not ok:
            return False, [], msg

        try:
            ok2, out, err = self._run('cat /root/usuarios.db 2>/dev/null || true')
            if not ok2:
                return False, [], err or 'No se pudo leer /root/usuarios.db'

            users_map: dict[str, int] = {}
            for raw in out.splitlines():
                line = raw.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 1:
                    continue

                username = parts[0].strip()
                if not _USERNAME_RE.match(username):
                    continue

                limit = 1
                if len(parts) >= 2:
                    try:
                        limit = int(parts[1])
                    except ValueError:
                        limit = 1
                users_map[username] = max(1, limit)

            shadow_expiry: dict[str, int] = {}
            ok2, shadow_out, _ = self._run("awk -F: '{print $1\":\"$8}' /etc/shadow 2>/dev/null || true")
            if ok2 and shadow_out.strip():
                for row in shadow_out.splitlines():
                    if ':' not in row:
                        continue
                    user, days_str = row.split(':', 1)
                    user = user.strip()
                    if not _USERNAME_RE.match(user):
                        continue
                    try:
                        shadow_expiry[user] = int(days_str.strip())
                    except ValueError:
                        continue

            users: list[dict[str, Any]] = []
            default_expiry = datetime.utcnow() + timedelta(days=3650)

            for username, limit in users_map.items():
                expiry_days = shadow_expiry.get(username)
                expiry_date = default_expiry
                if isinstance(expiry_days, int) and expiry_days > 0 and expiry_days < 90000:
                    expiry_date = datetime(1970, 1, 1) + timedelta(days=expiry_days)

                password = self._sftp_read(f'/etc/VPNPro/senha/{username}', '').strip()
                users.append(
                    {
                        'username': username,
                        'limit': limit,
                        'expiry_date': expiry_date,
                        'password': password,
                    }
                )

            return True, users, ''
        finally:
            self.disconnect()

    def create_user(
        self, username: str, password: str, days: int, limit: int
    ) -> tuple[bool, str]:
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'
        if len(password) < 4:
            return False, 'La contraseña debe tener al menos 4 caracteres'
        if days < 1:
            return False, 'Los días deben ser al menos 1'
        if limit < 1:
            return False, 'El límite debe ser al menos 1'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar al servidor: {msg}'
        try:
            # Check if user already exists
            ok2, out, _ = self._run(f'id {username} 2>/dev/null && echo EXISTS || echo NEW')
            if 'EXISTS' in out:
                return False, f"El usuario '{username}' ya existe en el servidor"

            expiry = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')

            ok2, _, err = self._run(
                f'useradd --badname -e {expiry} -M -s /bin/false {username}'
            )
            if not ok2 and 'already exists' not in err:
                return False, f'Error al crear usuario del sistema: {err}'

            ok2, err2 = self._set_password_stdin(username, password)
            if not ok2:
                self._run(f'userdel --force {username} 2>/dev/null')
                return False, f'Error al establecer contraseña: {err2}'

            # Append to usuarios.db
            ok2, out2, _ = self._run('cat /root/usuarios.db 2>/dev/null || echo ""')
            current_db = out2 if ok2 else ''
            new_db = (current_db.rstrip('\n') + f'\n{username} {limit}\n').lstrip('\n')
            self._sftp_write('/root/usuarios.db', new_db)

            # Store password file
            self._run('mkdir -p /etc/VPNPro/senha')
            self._sftp_write(f'/etc/VPNPro/senha/{username}', password)

            return True, f"Usuario '{username}' creado exitosamente (expira: {expiry})"
        finally:
            self.disconnect()

    def delete_user(self, username: str) -> tuple[bool, str]:
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            self._run(f'pkill -u {username} 2>/dev/null; true')

            ok2, _, err = self._run(f'userdel --force {username} 2>&1')

            # Remove from usuarios.db using SFTP
            db_content = self._sftp_read('/root/usuarios.db', '')
            filtered = '\n'.join(
                line for line in db_content.splitlines()
                if not line.startswith(f'{username} ')
            )
            self._sftp_write('/root/usuarios.db', filtered + '\n')

            # Remove password file
            self._sftp_remove(f'/etc/VPNPro/senha/{username}')

            return True, f"Usuario '{username}' eliminado"
        finally:
            self.disconnect()

    def change_password(self, username: str, new_password: str) -> tuple[bool, str]:
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'
        if len(new_password) < 4:
            return False, 'La contraseña debe tener al menos 4 caracteres'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            ok2, err = self._set_password_stdin(username, new_password)
            if not ok2:
                return False, f'Error: {err}'
            self._sftp_write(f'/etc/VPNPro/senha/{username}', new_password)
            return True, 'Contraseña cambiada exitosamente'
        finally:
            self.disconnect()

    def change_limit(self, username: str, new_limit: int) -> tuple[bool, str]:
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            db_content = self._sftp_read('/root/usuarios.db', '')
            new_lines = []
            for line in db_content.splitlines():
                if line.startswith(f'{username} '):
                    new_lines.append(f'{username} {new_limit}')
                else:
                    new_lines.append(line)
            self._sftp_write('/root/usuarios.db', '\n'.join(new_lines) + '\n')
            return True, 'Límite de conexiones actualizado'
        finally:
            self.disconnect()

    def change_expiry(self, username: str, days: int) -> tuple[bool, str]:
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'
        if days < 1:
            return False, 'Los días deben ser al menos 1'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            expiry = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')
            ok2, _, err = self._run(f'chage -E {expiry} {username}')
            if not ok2:
                return False, f'Error: {err}'
            return True, f'Expiración actualizada a {expiry}'
        finally:
            self.disconnect()

    def set_expiry_date(self, username: str, expiry_date: datetime) -> tuple[bool, str]:
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            expiry = expiry_date.strftime('%Y-%m-%d')
            ok2, _, err = self._run(f'chage -E {expiry} {username}')
            if not ok2:
                return False, f'Error: {err}'
            return True, f'Expiración ajustada a {expiry}'
        finally:
            self.disconnect()

    def block_user(self, username: str) -> tuple[bool, str]:
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            # Lock account and terminate active sessions.
            self._run(f'pkill -u {username} 2>/dev/null; true')
            ok2, _, err = self._run(f'passwd -l {username} 2>&1')
            if not ok2:
                return False, f'Error al bloquear usuario: {err}'
            return True, f"Usuario '{username}' bloqueado"
        finally:
            self.disconnect()

    def unblock_user(self, username: str) -> tuple[bool, str]:
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            ok2, _, err = self._run(f'passwd -u {username} 2>&1')
            if not ok2:
                return False, f'Error al desbloquear usuario: {err}'
            return True, f"Usuario '{username}' desbloqueado"
        finally:
            self.disconnect()

    def schedule_demo_deletion(self, username: str, hours: int = 2) -> tuple[bool, str]:
        """Schedule automatic demo user deletion after *hours*."""
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'
        if hours < 1:
            return False, 'Las horas deben ser al menos 1'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            seconds = int(hours * 3600)
            cmd = (
                "nohup sh -c '"
                f"sleep {seconds}; "
                f"pkill -u {username} 2>/dev/null; "
                f"userdel --force {username} 2>/dev/null; "
                f"sed -i \"/^{username} /d\" /root/usuarios.db 2>/dev/null; "
                f"rm -f /etc/VPNPro/senha/{username} 2>/dev/null"
                "' >/dev/null 2>&1 &"
            )
            ok2, _, err = self._run(cmd)
            if not ok2:
                return False, err or 'No se pudo programar la eliminación automática'
            return True, 'Eliminación automática programada'
        finally:
            self.disconnect()
