from __future__ import annotations

from datetime import datetime, timedelta
from functools import wraps
import re
import io
import os
import json
import shutil
import sqlite3
import zipfile
import tempfile
import subprocess
import secrets
import string
import time
import socket
import math
from threading import Lock
from sqlalchemy import text, func
from sqlalchemy.orm import joinedload

from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify, send_file, current_app
from flask_login import login_required, current_user, logout_user

from models import db, Admin, Server, Reseller, VpnUser, CreditMovement
from services.ssh_service import SSHService

admin_bp = Blueprint('admin', __name__)
VPN_USERNAME_PATTERN = re.compile(r'^[A-ZÑ]+-[A-ZÑ]+$')
SYSTEM_ADMIN_RESELLER_NOTE = '__SYSTEM_ADMIN_OWNER__'
DEMO_MAX_HOURS = 1
PACKAGE_OPTIONS = {
    'demo_1h': {'label': 'Demo 1 hora', 'hours': 1, 'months': 0, 'credits': 0},
    '1m': {'label': '1 Mes', 'days': 30, 'months': 1, 'credits': 1},
    '3m': {'label': '3 Meses', 'days': 90, 'months': 3, 'credits': 3},
    '6m': {'label': '6 Meses', 'days': 180, 'months': 6, 'credits': 6},
    '12m': {'label': '12 Meses', 'days': 360, 'months': 12, 'credits': 12},
}

_RUNTIME_CACHE: dict[str, tuple[float, object]] = {}
_RUNTIME_CACHE_LOCK = Lock()
_SERVER_INFO_TTL_SECONDS = 25
_PORT_DETAILS_TTL_SECONDS = 20


def _cache_get(cache_key: str, ttl_seconds: int) -> object | None:
    now = time.monotonic()
    with _RUNTIME_CACHE_LOCK:
        entry = _RUNTIME_CACHE.get(cache_key)
        if not entry:
            return None
        expires_at, value = entry
        if expires_at <= now:
            _RUNTIME_CACHE.pop(cache_key, None)
            return None
        return value


def _cache_set(cache_key: str, ttl_seconds: int, value: object) -> object:
    expires_at = time.monotonic() + max(1, int(ttl_seconds))
    with _RUNTIME_CACHE_LOCK:
        _RUNTIME_CACHE[cache_key] = (expires_at, value)
    return value


def _cached_server_info(server: Server) -> tuple[bool, dict[str, str], str]:
    cache_key = f'server-info:{server.id}'
    cached = _cache_get(cache_key, _SERVER_INFO_TTL_SECONDS)
    if cached is not None:
        return cached  # type: ignore[return-value]

    svc = SSHService(server)
    result = svc.get_server_info()
    return _cache_set(cache_key, _SERVER_INFO_TTL_SECONDS, result)  # type: ignore[return-value]


def _cached_port_modules_details(server: Server) -> tuple[bool, dict[str, dict], str]:
    cache_key = f'port-details:{server.id}'
    cached = _cache_get(cache_key, _PORT_DETAILS_TTL_SECONDS)
    if cached is not None:
        return cached  # type: ignore[return-value]

    svc = SSHService(server)
    result = svc.get_port_modules_details()
    return _cache_set(cache_key, _PORT_DETAILS_TTL_SECONDS, result)  # type: ignore[return-value]


def _read_cpu_times() -> tuple[int, int] | None:
    """Return (idle, total) cpu jiffies from /proc/stat."""
    try:
        with open('/proc/stat', 'r', encoding='utf-8') as fh:
            first = fh.readline().strip().split()
        if not first or first[0] != 'cpu' or len(first) < 5:
            return None
        nums = [int(v) for v in first[1:] if v.isdigit()]
        if len(nums) < 5:
            return None
        idle = nums[3] + nums[4]  # idle + iowait
        total = sum(nums)
        return idle, total
    except Exception:
        return None


def _local_cpu_usage() -> str:
    """Approximate local CPU usage percentage for panel host."""
    p1 = _read_cpu_times()
    if not p1:
        return 'N/A'
    time.sleep(0.18)
    p2 = _read_cpu_times()
    if not p2:
        return 'N/A'

    idle_delta = p2[0] - p1[0]
    total_delta = p2[1] - p1[1]
    if total_delta <= 0:
        return 'N/A'

    used_pct = max(0.0, min(100.0, (1.0 - (idle_delta / total_delta)) * 100.0))
    return f'{used_pct:.1f}%'


def _local_ram_usage() -> str:
    """Return local RAM usage in MB and percentage from /proc/meminfo."""
    try:
        mem_total_kb = None
        mem_avail_kb = None
        with open('/proc/meminfo', 'r', encoding='utf-8') as fh:
            for line in fh:
                if line.startswith('MemTotal:'):
                    mem_total_kb = int(line.split()[1])
                elif line.startswith('MemAvailable:'):
                    mem_avail_kb = int(line.split()[1])
                if mem_total_kb is not None and mem_avail_kb is not None:
                    break

        if not mem_total_kb or mem_avail_kb is None:
            return 'N/A'

        used_kb = max(0, mem_total_kb - mem_avail_kb)
        used_mb = used_kb / 1024.0
        total_mb = mem_total_kb / 1024.0
        pct = (used_kb / mem_total_kb) * 100.0 if mem_total_kb > 0 else 0.0
        return f'{used_mb:.0f}/{total_mb:.0f} MB ({pct:.0f}%)'
    except Exception:
        return 'N/A'


def _sqlite_db_path() -> str:
    uri = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
    prefix = 'sqlite:///'
    if not uri.startswith(prefix):
        raise ValueError('Solo se soporta backup/restauracion con SQLite.')
    return uri[len(prefix):]


def _find_zip_member(names: list[str], target_name: str) -> str | None:
    target_lower = target_name.lower()
    for name in names:
        if name.lower() == target_lower:
            return name
    for name in names:
        if name.lower().endswith('/' + target_lower) or name.lower().endswith('\\' + target_lower):
            return name
    return None


def _backups_dir() -> str:
    path = os.path.join(current_app.instance_path, 'backups')
    os.makedirs(path, exist_ok=True)
    return path


def _list_backups() -> list[dict]:
    path = _backups_dir()
    items = []
    for name in os.listdir(path):
        if not name.lower().endswith('.zip'):
            continue
        full_path = os.path.join(path, name)
        if not os.path.isfile(full_path):
            continue
        stat = os.stat(full_path)
        items.append({
            'name': name,
            'size_bytes': stat.st_size,
            'modified_at': datetime.utcfromtimestamp(stat.st_mtime),
        })
    items.sort(key=lambda x: x['modified_at'], reverse=True)
    return items


def _safe_backup_file(filename: str) -> str | None:
    safe_name = os.path.basename(filename)
    if safe_name != filename or not safe_name.lower().endswith('.zip'):
        return None
    full_path = os.path.join(_backups_dir(), safe_name)
    if not os.path.isfile(full_path):
        return None
    return full_path


def _settings_file() -> str:
    os.makedirs(current_app.instance_path, exist_ok=True)
    return os.path.join(current_app.instance_path, 'panel_settings.json')


def _load_settings() -> dict:
    path = _settings_file()
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_settings(settings: dict) -> None:
    path = _settings_file()
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(settings, fh, ensure_ascii=True, indent=2)


def _get_primary_server_id() -> int | None:
    value = _load_settings().get('primary_server_id')
    return value if isinstance(value, int) else None


def _set_primary_server_id(server_id: int | None) -> None:
    settings = _load_settings()
    if server_id is None:
        settings.pop('primary_server_id', None)
    else:
        settings['primary_server_id'] = server_id
    _save_settings(settings)


def _get_first_connect_opened_ids() -> set[int]:
    value = _load_settings().get('first_connect_opened_server_ids', [])
    if not isinstance(value, list):
        return set()
    parsed: set[int] = set()
    for item in value:
        if isinstance(item, int):
            parsed.add(item)
    return parsed


def _mark_first_connect_opened(server_id: int) -> None:
    ids = _get_first_connect_opened_ids()
    ids.add(server_id)
    settings = _load_settings()
    settings['first_connect_opened_server_ids'] = sorted(ids)
    _save_settings(settings)


def _open_initial_ports_once(server: Server, svc: SSHService) -> tuple[list[str], list[str]]:
    tcp_ports = current_app.config.get('AUTO_OPEN_TCP_PORTS', []) or []
    udp_ports = current_app.config.get('AUTO_OPEN_UDP_PORTS', []) or []

    target_protocols: dict[int, list[str]] = {}
    for p in tcp_ports:
        target_protocols.setdefault(int(p), [])
        if 'tcp' not in target_protocols[int(p)]:
            target_protocols[int(p)].append('tcp')
    for p in udp_ports:
        target_protocols.setdefault(int(p), [])
        if 'udp' not in target_protocols[int(p)]:
            target_protocols[int(p)].append('udp')

    opened: list[str] = []
    failed: list[str] = []

    for p, protocols in sorted(target_protocols.items()):
        okp, msgp = svc.open_port_rules(p, protocols)
        if okp:
            opened.append(f"{p}/{'/'.join(protocols)}")
        else:
            failed.append(f"{p}/{'/'.join(protocols)} ({msgp})")

    if not failed:
        _mark_first_connect_opened(server.id)

    return opened, failed


def _resolve_package(package_code: str) -> dict:
    return PACKAGE_OPTIONS.get(package_code, PACKAGE_OPTIONS['1m'])


def _can_charge_credits(owner: Reseller, credits_needed: int) -> tuple[bool, str]:
    if credits_needed <= 0:
        return True, ''
    if owner.note == SYSTEM_ADMIN_RESELLER_NOTE:
        return True, ''
    if (owner.panel_credits or 0) < credits_needed:
        return False, f'Creditos insuficientes. Requiere {credits_needed} y tiene {owner.panel_credits or 0}.'
    return True, ''


def _log_credit_movement(reseller: Reseller, delta: int, reason: str) -> None:
    db.session.add(
        CreditMovement(
            reseller_id=reseller.id,
            delta=delta,
            balance_after=reseller.panel_credits or 0,
            reason=reason,
        )
    )


def _generate_demo_username() -> str:
    suffix = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(4))
    return f'DEMO-{suffix}'


def _generate_demo_password(length: int = 10) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def _get_or_create_system_reseller(server_id: int) -> Reseller:
    # Friendly, stable naming for system owner records used by sync.
    system_username = f"Admin-{server_id}"

    # 1) Preferred lookup by server + system note.
    existing = Reseller.query.filter_by(
        server_id=server_id,
        note=SYSTEM_ADMIN_RESELLER_NOTE,
    ).first()
    if existing:
        if existing.username != system_username:
            existing.username = system_username
            db.session.flush()
        return existing

    # 2) Legacy fallback: old generated username pattern.
    legacy_username = f"__ADMIN_OWNER_{server_id}__"
    legacy = Reseller.query.filter_by(username=legacy_username).first()
    if legacy:
        legacy.username = system_username
        legacy.note = SYSTEM_ADMIN_RESELLER_NOTE
        legacy.server_id = server_id
        if legacy.is_active:
            legacy.is_active = False
        db.session.flush()
        return legacy

    r = Reseller(
        username=system_username,
        email='system@local',
        server_id=server_id,
        max_connections=9999,
        is_active=False,
        note=SYSTEM_ADMIN_RESELLER_NOTE,
    )
    r.set_password(f'system-{server_id}-{datetime.utcnow().timestamp()}')
    db.session.add(r)
    db.session.flush()
    return r


def _pick_server_transfer_target(source_server_id: int) -> Server | None:
    preferred_primary_id = _get_primary_server_id()
    if preferred_primary_id and preferred_primary_id != source_server_id:
        preferred = db.session.get(Server, preferred_primary_id)
        if preferred and preferred.is_active:
            return preferred

    return (
        Server.query
        .filter(Server.id != source_server_id, Server.is_active.is_(True))
        .order_by(Server.id.asc())
        .first()
    )


def _migrate_vpn_user_to_server(user: VpnUser, target_server: Server) -> tuple[bool, str]:
    if not user.is_active:
        return True, 'Usuario inactivo movido solo en base de datos.'

    password = (user.password or '').strip() or _generate_demo_password(12)
    now = datetime.utcnow()
    remaining_seconds = (user.expiry_date - now).total_seconds()
    create_days = max(1, int(math.ceil(max(remaining_seconds, 3600) / 86400.0)))

    target_svc = SSHService(target_server)
    ok, msg = target_svc.create_user(user.username, password, create_days, max(1, user.connection_limit))
    if not ok:
        return False, msg

    ok, msg = target_svc.set_expiry_date(user.username, user.expiry_date)
    if not ok:
        target_svc.delete_user(user.username)
        return False, f'No se pudo ajustar expiración: {msg}'

    if remaining_seconds > 0 and remaining_seconds < 86400:
        hours = max(1, int(math.ceil(remaining_seconds / 3600.0)))
        sched_ok, sched_msg = target_svc.schedule_demo_deletion(user.username, hours)
        if not sched_ok:
            target_svc.delete_user(user.username)
            return False, f'No se pudo programar expiración corta: {sched_msg}'

    if user.is_blocked:
        ok, msg = target_svc.block_user(user.username)
        if not ok:
            target_svc.delete_user(user.username)
            return False, f'No se pudo restaurar estado bloqueado: {msg}'

    user.password = password
    return True, 'Usuario migrado al servidor destino.'


def _transfer_server_records(source_server: Server, target_server: Server) -> tuple[bool, dict[str, int], str, list[str]]:
    migrated_usernames: list[str] = []
    stats = {
        'resellers': 0,
        'users': 0,
        'admin_users': 0,
    }

    source_users = (
        VpnUser.query
        .filter_by(server_id=source_server.id)
        .order_by(VpnUser.id.asc())
        .all()
    )

    for user in source_users:
        ok, msg = _migrate_vpn_user_to_server(user, target_server)
        if not ok:
            return False, stats, f"{user.username}: {msg}", migrated_usernames
        if user.is_active:
            migrated_usernames.append(user.username)

    target_admin_owner = _get_or_create_system_reseller(target_server.id)
    source_admin_owner = Reseller.query.filter_by(
        server_id=source_server.id,
        note=SYSTEM_ADMIN_RESELLER_NOTE,
    ).first()

    normal_resellers = (
        Reseller.query
        .filter(Reseller.server_id == source_server.id, Reseller.note != SYSTEM_ADMIN_RESELLER_NOTE)
        .all()
    )
    for reseller in normal_resellers:
        reseller.server_id = target_server.id
        stats['resellers'] += 1

    for user in source_users:
        user.server_id = target_server.id
        stats['users'] += 1

    if source_admin_owner:
        admin_owned_users = VpnUser.query.filter_by(reseller_id=source_admin_owner.id).all()
        for user in admin_owned_users:
            user.reseller_id = target_admin_owner.id
            stats['admin_users'] += 1

        CreditMovement.query.filter_by(reseller_id=source_admin_owner.id).delete(synchronize_session=False)
        db.session.delete(source_admin_owner)

    db.session.flush()
    return True, stats, '', migrated_usernames


def _sync_server_users_data(server: Server) -> tuple[bool, dict[str, int], str]:
    svc = SSHService(server)
    ok, remote_users, err = svc.list_users_for_sync()
    if not ok:
        return False, {}, err

    owner = _get_or_create_system_reseller(server.id)

    created = 0
    updated = 0
    reactivated = 0
    deactivated = 0

    server_users = (
        VpnUser.query
        .filter_by(server_id=server.id)
        .order_by(VpnUser.id.desc())
        .all()
    )
    existing_by_norm: dict[str, VpnUser] = {}
    for panel_user in server_users:
        key = panel_user.username.strip().upper()
        if key and key not in existing_by_norm:
            existing_by_norm[key] = panel_user

    remote_norm_keys: set[str] = set()

    for remote_data in remote_users:
        username_raw = (remote_data.get('username') or '').strip()
        if not username_raw:
            continue

        username_norm = username_raw.upper()
        remote_norm_keys.add(username_norm)

        remote_limit = max(1, int(remote_data.get('limit') or 1))
        remote_expiry = remote_data.get('expiry_date') or (datetime.utcnow() + timedelta(days=3650))
        remote_password = (remote_data.get('password') or '').strip()
        fallback_password = _generate_demo_password(12)

        existing = existing_by_norm.get(username_norm)

        if not existing:
            db.session.add(
                VpnUser(
                    username=username_raw,
                    password=remote_password or fallback_password,
                    connection_limit=remote_limit,
                    expiry_date=remote_expiry,
                    reseller_id=owner.id,
                    server_id=server.id,
                    is_active=True,
                )
            )
            created += 1
            continue

        changed = False
        if existing.username != username_raw:
            existing.username = username_raw
            changed = True
        if not existing.is_active:
            existing.is_active = True
            reactivated += 1
            changed = True
        if existing.connection_limit != remote_limit:
            existing.connection_limit = remote_limit
            changed = True
        if existing.expiry_date != remote_expiry:
            existing.expiry_date = remote_expiry
            changed = True
        if remote_password and existing.password != remote_password:
            existing.password = remote_password
            changed = True
        elif not existing.password:
            existing.password = fallback_password
            changed = True

        if changed:
            updated += 1

    active_server_users = VpnUser.query.filter_by(server_id=server.id, is_active=True).all()
    for panel_user in active_server_users:
        if panel_user.username.strip().upper() not in remote_norm_keys:
            panel_user.is_active = False
            deactivated += 1

    remote_total = len(remote_norm_keys)
    unchanged = max(0, remote_total - created - updated)

    return True, {
        'created': created,
        'updated': updated,
        'reactivated': reactivated,
        'deactivated': deactivated,
        'remote_total': remote_total,
        'unchanged': unchanged,
    }, ''


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not isinstance(current_user, Admin):
            flash('Acceso restringido a administradores.', 'danger')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return login_required(decorated)


# ──────────────────────────────────────────────────────────
# Dashboard
# ──────────────────────────────────────────────────────────

@admin_bp.route('/')
@admin_required
def dashboard():
    total_servers = Server.query.count()
    total_resellers = Reseller.query.count()
    active_resellers = Reseller.query.filter_by(is_active=True).count()
    total_vpn_users = VpnUser.query.filter_by(is_active=True).count()
    servers = Server.query.order_by(Server.created_at.desc()).all()
    preferred_primary_id = _get_primary_server_id()
    primary_server = None
    if preferred_primary_id is not None:
        primary_server = db.session.get(Server, preferred_primary_id)
    if not primary_server:
        primary_server = Server.query.order_by(Server.id.asc()).first()
        if primary_server:
            _set_primary_server_id(primary_server.id)
    server_metrics: dict[int, dict[str, str | bool]] = {}

    for sv in servers:
        ok, info, _ = _cached_server_info(sv)
        server_metrics[sv.id] = {
            'ok': ok,
            'cpu': info.get('cpu', 'N/A') if ok else 'N/A',
            'ram': info.get('ram', 'N/A') if ok else 'N/A',
            'disk': info.get('disk', 'N/A') if ok else 'N/A',
            'uptime': info.get('uptime', 'N/A') if ok else 'N/A',
            'online': info.get('online', '0') if ok else '0',
        }

    primary_metrics = server_metrics.get(primary_server.id) if primary_server else None
    recent_users = (
        VpnUser.query
        .options(joinedload(VpnUser.reseller))
        .order_by(VpnUser.created_at.desc())
        .limit(10)
        .all()
    )
    local_panel_cpu = _local_cpu_usage()
    local_panel_ram = _local_ram_usage()
    local_panel_host = socket.gethostname() or 'panel-web'
    try:
        panel_database_path = _sqlite_db_path()
    except ValueError:
        panel_database_path = current_app.config.get('SQLALCHEMY_DATABASE_URI', 'N/A')

    return render_template(
        'admin/dashboard.html',
        total_servers=total_servers,
        total_resellers=total_resellers,
        active_resellers=active_resellers,
        total_vpn_users=total_vpn_users,
        servers=servers,
        primary_server=primary_server,
        primary_metrics=primary_metrics,
        server_metrics=server_metrics,
        recent_users=recent_users,
        backup_files=_list_backups(),
        local_panel_cpu=local_panel_cpu,
        local_panel_ram=local_panel_ram,
        local_panel_host=local_panel_host,
        panel_data_dir=current_app.instance_path,
        panel_database_path=panel_database_path,
    )


@admin_bp.route('/account', methods=['POST'])
@admin_required
def update_account():
    current_password = request.form.get('current_password', '')
    new_max_connections = request.form.get('max_connections', '', type=int)
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not current_user.check_password(current_password):
        flash('La contraseña actual no es correcta.', 'danger')
        return redirect(url_for('admin.dashboard'))

    changed = False
    password_changed = False

    if new_max_connections is not None and new_max_connections != current_user.max_connections:
        if new_max_connections < 0:
            flash('El límite de conexiones no puede ser negativo.', 'danger')
            return redirect(url_for('admin.dashboard'))
        current_user.max_connections = new_max_connections
        changed = True

    if new_password:
        if len(new_password) < 6:
            flash('La nueva contraseña debe tener al menos 6 caracteres.', 'danger')
            return redirect(url_for('admin.dashboard'))
        if new_password != confirm_password:
            flash('La confirmación de contraseña no coincide.', 'danger')
            return redirect(url_for('admin.dashboard'))
        current_user.set_password(new_password)
        password_changed = True
        changed = True

    if not changed:
        flash('No se detectaron cambios para guardar.', 'warning')
        return redirect(url_for('admin.dashboard'))

    db.session.commit()
    if password_changed:
        logout_user()
        flash('Contraseña actualizada. Inicia sesión nuevamente.', 'success')
        return redirect(url_for('auth.login'))

    flash('Credenciales de administrador actualizadas.', 'success')
    return redirect(url_for('admin.dashboard'))


# ──────────────────────────────────────────────────────────
# Servers
# ──────────────────────────────────────────────────────────

@admin_bp.route('/servers', methods=['GET', 'POST'])
@admin_required
def servers():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        ip = request.form.get('ip', '').strip()
        port = int(request.form.get('port', 22) or 22)
        ssh_user = request.form.get('ssh_user', 'root').strip() or 'root'
        ssh_password = request.form.get('ssh_password', '')
        description = request.form.get('description', '').strip()

        if not name or not ip or not ssh_password:
            flash('Nombre, IP y contraseña SSH son obligatorios.', 'danger')
        else:
            server = Server(
                name=name, ip=ip, port=port,
                ssh_user=ssh_user, description=description,
            )
            server.set_ssh_password(ssh_password)
            db.session.add(server)
            db.session.commit()
            flash(f"Servidor '{name}' agregado.", 'success')
        return redirect(url_for('admin.servers'))

    all_servers = Server.query.order_by(Server.name).all()
    port_modules_status: dict[int, dict[str, dict]] = {}
    transfer_preview: dict[int, dict[str, str | int | None]] = {}
    reseller_counts_raw = (
        db.session.query(Reseller.server_id, func.count(Reseller.id))
        .filter(Reseller.note != SYSTEM_ADMIN_RESELLER_NOTE)
        .group_by(Reseller.server_id)
        .all()
    )
    user_counts_raw = (
        db.session.query(VpnUser.server_id, func.count(VpnUser.id))
        .group_by(VpnUser.server_id)
        .all()
    )
    reseller_counts = {sid: int(total) for sid, total in reseller_counts_raw}
    user_counts = {sid: int(total) for sid, total in user_counts_raw}

    for sv in all_servers:
        ok, status, _ = _cached_port_modules_details(sv)
        if ok:
            port_modules_status[sv.id] = status
        else:
            port_modules_status[sv.id] = {
                'http_custom': {'label': 'HTTP', 'active': None, 'port': '-', 'proto': 'tcp'},
                'ssl_tunnel': {'label': 'SSL Tunnel', 'active': None, 'port': '-', 'proto': 'tcp'},
                'websocket_tunnel': {'label': 'WebSocket Tunnel', 'active': None, 'port': '-', 'proto': 'tcp'},
                'badvpn_udp': {'label': 'BadVPN UDPGW', 'active': None, 'port': '-', 'proto': 'udp'},
                'checkuser': {'label': 'CheckUser', 'active': None, 'port': '-', 'proto': 'tcp'},
            }

        target_server = _pick_server_transfer_target(sv.id)
        transfer_preview[sv.id] = {
            'target_name': target_server.name if target_server else None,
            'reseller_count': reseller_counts.get(sv.id, 0),
            'user_count': user_counts.get(sv.id, 0),
        }

    return render_template(
        'admin/servers.html',
        servers=all_servers,
        primary_server_id=_get_primary_server_id(),
        port_modules_status=port_modules_status,
        transfer_preview=transfer_preview,
    )


@admin_bp.route('/servers/<int:server_id>/edit', methods=['POST'])
@admin_required
def edit_server(server_id: int):
    server = db.session.get(Server, server_id)
    if not server:
        flash('Servidor no encontrado.', 'danger')
        return redirect(url_for('admin.servers'))

    name = request.form.get('name', '').strip()
    ip = request.form.get('ip', '').strip()
    try:
        port = int(request.form.get('port', 22) or 22)
    except ValueError:
        port = 22
    ssh_user = request.form.get('ssh_user', 'root').strip() or 'root'
    ssh_password = request.form.get('ssh_password', '').strip()
    description = request.form.get('description', '').strip()

    if not name or not ip:
        flash('Nombre e IP son obligatorios.', 'danger')
        return redirect(url_for('admin.servers'))

    server.name = name
    server.ip = ip
    server.port = port
    server.ssh_user = ssh_user
    server.description = description
    
    if ssh_password:
        server.set_ssh_password(ssh_password)

    db.session.commit()
    flash(f"Servidor '{name}' actualizado.", 'success')
    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/<int:server_id>/delete', methods=['POST'])
@admin_required
def delete_server(server_id: int):
    server = db.session.get(Server, server_id)
    if not server:
        flash('Servidor no encontrado.', 'danger')
        return redirect(url_for('admin.servers'))

    server_name = server.name
    target_server = _pick_server_transfer_target(server.id)
    if not target_server:
        flash('No se puede eliminar: necesitas al menos otro servidor activo para transferir revendedores y usuarios VPN.', 'danger')
        return redirect(url_for('admin.servers'))

    was_primary = _get_primary_server_id() == server.id
    migrated_usernames: list[str] = []

    try:
        ok_transfer, stats, err_transfer, migrated_usernames = _transfer_server_records(server, target_server)
        if not ok_transfer:
            raise RuntimeError(
                f"No se pudo transferir el contenido del servidor al principal '{target_server.name}': {err_transfer}"
            )

        db.session.delete(server)
        db.session.commit()

        if was_primary:
            try:
                _set_primary_server_id(target_server.id)
            except Exception:
                current_app.logger.exception(
                    'No se pudo actualizar primary_server_id tras eliminar servidor id=%s',
                    server_id,
                )
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception('Error eliminando servidor id=%s', server_id)
        for username in migrated_usernames:
            try:
                SSHService(target_server).delete_user(username)
            except Exception:
                current_app.logger.exception(
                    'No se pudo revertir la migracion del usuario %s al servidor destino %s',
                    username,
                    target_server.id,
                )

        flash(
            (
                f"No se pudo eliminar '{server_name}'. La transferencia hacia '{target_server.name}' fue cancelada: "
                f"{str(exc)[:180]}"
            ),
            'danger',
        )
        return redirect(url_for('admin.servers'))

    flash(
        (
            f"Servidor '{server_name}' eliminado. Revendedores y usuarios VPN fueron transferidos a '{target_server.name}'."
        ),
        'success',
    )
    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/<int:server_id>/set-primary', methods=['POST'])
@admin_required
def set_primary_server(server_id: int):
    server = db.session.get(Server, server_id)
    if not server:
        flash('Servidor no encontrado.', 'danger')
        return redirect(url_for('admin.servers'))

    _set_primary_server_id(server.id)
    flash(f"Servidor principal actualizado: '{server.name}'.", 'success')
    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/<int:server_id>/test', methods=['POST'])
@admin_required
def test_server(server_id: int):
    server = db.session.get(Server, server_id)
    if not server:
        return jsonify({'ok': False, 'msg': 'Servidor no encontrado'})
    svc = SSHService(server)
    ok, msg = svc.test_connection()
    if not ok:
        return jsonify({'ok': False, 'msg': msg})

    ports_msg = ''
    if current_app.config.get('AUTO_OPEN_PORTS_ON_FIRST_CONNECT', True):
        opened_ids = _get_first_connect_opened_ids()
        if server.id not in opened_ids:
            opened, failed = _open_initial_ports_once(server, svc)

            if opened and not failed:
                ports_msg = f" Puertos abiertos automaticamente: {', '.join(opened)}"
            elif opened and failed:
                ports_msg = (
                    f" Apertura parcial: abiertos {', '.join(opened)}. "
                    f"Fallidos: {' | '.join(failed)}"
                )
            elif failed:
                ports_msg = f" No se pudieron abrir puertos: {' | '.join(failed)}"

    return jsonify({'ok': True, 'msg': f'Conexión exitosa ✓{ports_msg}'})


@admin_bp.route('/servers/<int:server_id>/ports-status', methods=['GET'])
@admin_bp.route('/servers/<int:server_id>/ports-status/', methods=['GET'])
@admin_bp.route('/servers/ports-status/<int:server_id>', methods=['GET'])
@admin_required
def server_ports_status(server_id: int):
    try:
        server = db.session.get(Server, server_id)
        if not server:
            return jsonify({'ok': False, 'msg': 'Servidor no encontrado', 'status': {}}), 404

        svc = SSHService(server)
        ok, status, err = svc.get_port_modules_status()
        if not ok:
            return jsonify({'ok': False, 'msg': err, 'status': {}}), 200

        return jsonify({'ok': True, 'status': status})
    except Exception as ex:
        current_app.logger.exception('Error consultando estado de puertos en server id=%s', server_id)
        return jsonify({'ok': False, 'msg': f'Error interno: {str(ex)[:180]}', 'status': {}}), 500


@admin_bp.route('/servers/<int:server_id>/reboot', methods=['POST'])
@admin_required
def reboot_server(server_id: int):
    server = db.session.get(Server, server_id)
    if not server:
        flash('Servidor no encontrado.', 'danger')
        return redirect(url_for('admin.servers'))

    svc = SSHService(server)
    ok, msg = svc.reboot_server()
    if ok:
        flash(
            f"Reinicio enviado a '{server.name}'. Espera 1-2 minutos para que vuelva en línea.",
            'success',
        )
    else:
        flash(f"No se pudo reiniciar '{server.name}': {msg}", 'danger')
    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/<int:server_id>/open-port', methods=['POST'])
@admin_bp.route('/servers/<int:server_id>/open-port/', methods=['POST'])
@admin_bp.route('/servers/open-port/<int:server_id>', methods=['POST'])
@admin_required
def open_server_port(server_id: int):
    wants_json = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    def _json_or_redirect(ok: bool, msg: str, category: str = 'success'):
        if wants_json:
            return jsonify({'ok': ok, 'msg': msg}), (200 if ok else 400)
        flash(msg, category)
        return redirect(url_for('admin.servers'))

    try:
        server = db.session.get(Server, server_id)
        if not server:
            return _json_or_redirect(False, 'Servidor no encontrado.', 'danger')

        module = (request.form.get('module') or '').strip().lower()
        action = (request.form.get('action') or 'open').strip().lower()
        open_mode = (request.form.get('open_mode') or 'port_and_module').strip().lower()
        try:
            port = int(request.form.get('port', '0') or 0)
        except ValueError:
            port = 0

        if module not in {'http_custom', 'ssl_tunnel', 'websocket_tunnel', 'badvpn_udp', 'checkuser'}:
            return _json_or_redirect(False, 'Modulo de puertos invalido.', 'danger')

        if action not in {'open', 'close'}:
            return _json_or_redirect(False, 'Accion invalida.', 'danger')

        if open_mode not in {'port_and_module', 'port_only'}:
            open_mode = 'port_and_module'

        if action == 'close':
            svc = SSHService(server)
            if module == 'http_custom':
                ok, msg = svc.disable_http_custom_tunnel()
            elif module == 'ssl_tunnel':
                ok, msg = svc.disable_ssl_tunnel()
            elif module == 'badvpn_udp':
                ok, msg = svc.disable_badvpn_udpgw()
            elif module == 'checkuser':
                ok, msg = svc.uninstall_checkuser()
            else:
                ok, msg = svc.disable_websocket_tunnel()

            if ok:
                return _json_or_redirect(True, f"[{server.name}] {msg}", 'success')
            else:
                return _json_or_redirect(False, f"[{server.name}] Error al cerrar puerto: {msg}", 'danger')

        if port < 1 or port > 65535:
            return _json_or_redirect(False, 'Puerto invalido. Debe estar entre 1 y 65535.', 'danger')

        svc = SSHService(server)
        open_protocols = ['udp'] if module == 'badvpn_udp' else ['tcp']
        fw_ok, fw_msg = svc.open_port_rules(port, open_protocols)
        if not fw_ok:
            return _json_or_redirect(False, f"[{server.name}] No se pudo abrir el puerto en firewall: {fw_msg}", 'danger')

        if open_mode == 'port_only':
            return _json_or_redirect(True, f"[{server.name}] {fw_msg} Modo aplicado: solo apertura de puerto.", 'success')

        if module == 'http_custom':
            ok, msg = svc.setup_http_custom_tunnel(port)
        elif module == 'ssl_tunnel':
            ok, msg = svc.setup_ssl_tunnel(port)
        elif module == 'badvpn_udp':
            ok, msg = svc.setup_badvpn_udpgw(port)
        elif module == 'checkuser':
            ok, msg = svc.install_checkuser(port)
        else:
            ok, msg = svc.setup_websocket_tunnel(port)
        if ok:
            return _json_or_redirect(True, f"[{server.name}] {fw_msg} {msg}", 'success')
        else:
            return _json_or_redirect(False, f"[{server.name}] {fw_msg} No se pudo activar el modulo ({msg}).", 'warning')
    except Exception as ex:
        current_app.logger.exception('Error en open_server_port server id=%s', server_id)
        return _json_or_redirect(False, f'Error interno: {str(ex)[:180]}', 'danger')


@admin_bp.route('/servers/<int:server_id>/sync-users', methods=['POST'])
@admin_required
def sync_server_users(server_id: int):
    server = db.session.get(Server, server_id)
    if not server:
        flash('Servidor no encontrado.', 'danger')
        return redirect(url_for('admin.servers'))

    ok, stats, err = _sync_server_users_data(server)
    if not ok:
        flash(f'No se pudo sincronizar usuarios desde {server.name}: {err}', 'danger')
        return redirect(url_for('admin.servers'))

    db.session.commit()
    flash(
        (
            f"Sincronizacion completada en '{server.name}': "
            f"{stats['created']} nuevo(s), {stats['updated']} actualizado(s), "
            f"{stats['reactivated']} reactivado(s), {stats['deactivated']} desactivado(s), "
            f"{stats['unchanged']} sin cambios (total leidos: {stats['remote_total']})."
        ),
        'success',
    )
    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/<int:server_id>/checkuser/install', methods=['POST'])
@admin_required
def install_checkuser_on_server(server_id: int):
    server = db.session.get(Server, server_id)
    if not server:
        flash('Servidor no encontrado.', 'danger')
        return redirect(url_for('admin.servers'))

    port = request.form.get('checkuser_port', 2052, type=int)
    if not port or port < 1 or port > 65535:
        flash('Puerto invalido para CheckUser. Debe estar entre 1 y 65535.', 'danger')
        return redirect(url_for('admin.servers'))

    svc = SSHService(server)
    ok, msg = svc.install_checkuser(port)
    if ok:
        flash(f"[{server.name}] {msg}", 'success')
    else:
        flash(f"[{server.name}] No se pudo instalar CheckUser: {msg}", 'danger')
    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/<int:server_id>/checkuser/uninstall', methods=['POST'])
@admin_required
def uninstall_checkuser_on_server(server_id: int):
    server = db.session.get(Server, server_id)
    if not server:
        flash('Servidor no encontrado.', 'danger')
        return redirect(url_for('admin.servers'))

    svc = SSHService(server)
    ok, msg = svc.uninstall_checkuser()
    if ok:
        flash(f"[{server.name}] {msg}", 'success')
    else:
        flash(f"[{server.name}] No se pudo desinstalar CheckUser: {msg}", 'danger')
    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/sync-users-all', methods=['POST'])
@admin_required
def sync_all_servers_users():
    servers = Server.query.filter_by(is_active=True).order_by(Server.id.asc()).all()
    if not servers:
        flash('No hay servidores activos para sincronizar.', 'warning')
        return redirect(url_for('admin.servers'))

    total_created = 0
    total_updated = 0
    total_reactivated = 0
    total_deactivated = 0
    total_remote = 0
    total_unchanged = 0
    failed: list[str] = []

    for server in servers:
        ok, stats, err = _sync_server_users_data(server)
        if not ok:
            failed.append(f"{server.name}: {err}")
            continue
        total_created += stats['created']
        total_updated += stats['updated']
        total_reactivated += stats['reactivated']
        total_deactivated += stats['deactivated']
        total_remote += stats['remote_total']
        total_unchanged += stats['unchanged']

    db.session.commit()

    flash(
        (
            f'Sincronizacion masiva completada: {len(servers) - len(failed)}/{len(servers)} servidor(es) OK. '
            f'{total_created} nuevo(s), {total_updated} actualizado(s), '
            f'{total_reactivated} reactivado(s), {total_deactivated} desactivado(s), '
            f'{total_unchanged} sin cambios (total leidos: {total_remote}).'
        ),
        'success',
    )
    if failed:
        flash('Servidores con error: ' + ' | '.join(failed), 'warning')
    return redirect(url_for('admin.servers'))


@admin_bp.route('/servers/<int:server_id>/toggle', methods=['POST'])
@admin_required
def toggle_server(server_id: int):
    server = db.session.get(Server, server_id)
    if server:
        server.is_active = not server.is_active
        db.session.commit()
        state = 'activado' if server.is_active else 'desactivado'
        flash(f"Servidor '{server.name}' {state}.", 'success')
    return redirect(url_for('admin.servers'))


# ──────────────────────────────────────────────────────────
# Resellers
# ──────────────────────────────────────────────────────────

@admin_bp.route('/resellers', methods=['GET', 'POST'])
@admin_required
def resellers():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email = request.form.get('email', '').strip()
        server_id = request.form.get('server_id', type=int)
        max_connections = request.form.get('max_connections', 0, type=int)
        panel_credits = request.form.get('panel_credits', 0, type=int)
        note = request.form.get('note', '').strip()

        if not username or not password or not server_id:
            flash('Usuario, contraseña y servidor son obligatorios.', 'danger')
        elif not VPN_USERNAME_PATTERN.fullmatch(username):
            flash('El usuario del revendedor debe usar formato MAYUSCULAS-NOMBRE-APELLIDO.', 'danger')
        elif Reseller.query.filter_by(username=username).first():
            flash(f"El usuario '{username}' ya existe.", 'danger')
        else:
            r = Reseller(
                username=username, email=email,
                server_id=server_id,
                max_connections=max(0, max_connections or 0),
                panel_credits=max(0, panel_credits or 0),
                note=note,
            )
            r.set_password(password)
            db.session.add(r)
            db.session.flush()
            if (r.panel_credits or 0) > 0:
                _log_credit_movement(r, r.panel_credits, 'Credito inicial asignado por Admin')
            db.session.commit()
            flash(f"Revendedor '{username}' creado.", 'success')
        return redirect(url_for('admin.resellers'))

    all_resellers = (
        Reseller.query
        .options(joinedload(Reseller.server))
        .filter(Reseller.note != SYSTEM_ADMIN_RESELLER_NOTE)
        .order_by(Reseller.username)
        .all()
    )
    all_servers = Server.query.filter_by(is_active=True).all()
    credit_logs = (
        CreditMovement.query
        .join(Reseller, CreditMovement.reseller_id == Reseller.id)
        .filter(Reseller.note != SYSTEM_ADMIN_RESELLER_NOTE)
        .order_by(CreditMovement.created_at.desc())
        .limit(30)
        .all()
    )
    return render_template(
        'admin/resellers.html',
        resellers=all_resellers,
        servers=all_servers,
        credit_logs=credit_logs,
    )


@admin_bp.route('/resellers/<int:reseller_id>/edit', methods=['POST'])
@admin_required
def edit_reseller(reseller_id: int):
    r = db.session.get(Reseller, reseller_id)
    if not r:
        flash('Revendedor no encontrado.', 'danger')
        return redirect(url_for('admin.resellers'))

    old_credits = r.panel_credits or 0
    new_password = request.form.get('password', '')
    r.email = request.form.get('email', '').strip()
    r.server_id = request.form.get('server_id', type=int) or r.server_id
    r.max_connections = request.form.get('max_connections', r.max_connections, type=int)
    r.panel_credits = max(0, request.form.get('panel_credits', r.panel_credits, type=int) or 0)
    r.note = request.form.get('note', '').strip()
    if new_password:
        r.set_password(new_password)

    delta = (r.panel_credits or 0) - old_credits
    if delta != 0:
        action = 'Recarga manual' if delta > 0 else 'Descuento manual'
        _log_credit_movement(r, delta, f"{action} por admin {current_user.username}")

    db.session.commit()
    flash(f"Revendedor '{r.username}' actualizado.", 'success')
    return redirect(url_for('admin.resellers'))


@admin_bp.route('/resellers/<int:reseller_id>/toggle', methods=['POST'])
@admin_required
def toggle_reseller(reseller_id: int):
    r = db.session.get(Reseller, reseller_id)
    if r:
        r.is_active = not r.is_active
        db.session.commit()
        state = 'activado' if r.is_active else 'desactivado'
        flash(f"Revendedor '{r.username}' {state}.", 'success')
    return redirect(url_for('admin.resellers'))


@admin_bp.route('/resellers/<int:reseller_id>/delete', methods=['POST'])
@admin_required
def delete_reseller(reseller_id: int):
    r = db.session.get(Reseller, reseller_id)
    if not r:
        flash('Revendedor no encontrado.', 'danger')
        return redirect(url_for('admin.resellers'))
    if r.note == SYSTEM_ADMIN_RESELLER_NOTE:
        flash('No se puede eliminar el propietario interno del administrador.', 'danger')
        return redirect(url_for('admin.resellers'))

    moved_users = 0
    users_to_move = VpnUser.query.filter_by(reseller_id=r.id).all()
    for u in users_to_move:
        admin_owner = _get_or_create_system_reseller(u.server_id)
        u.reseller_id = admin_owner.id
        moved_users += 1

    # Remove credit history tied to the reseller to avoid FK constraint issues on delete.
    CreditMovement.query.filter_by(reseller_id=r.id).delete(synchronize_session=False)

    db.session.delete(r)
    db.session.commit()
    if moved_users > 0:
        flash(
            f"Revendedor '{r.username}' eliminado. {moved_users} usuario(s) fueron transferidos al Administrador.",
            'success',
        )
    else:
        flash(f"Revendedor '{r.username}' eliminado.", 'success')
    return redirect(url_for('admin.resellers'))


@admin_bp.route('/resellers/<int:reseller_id>/add-credits', methods=['POST'])
@admin_required
def add_reseller_credits(reseller_id: int):
    r = db.session.get(Reseller, reseller_id)
    if not r:
        flash('Revendedor no encontrado.', 'danger')
        return redirect(url_for('admin.resellers'))

    try:
        amount = int(request.form.get('amount', 0))
    except (ValueError, TypeError):
        flash('Cantidad de créditos inválida.', 'danger')
        return redirect(url_for('admin.resellers'))

    if amount <= 0:
        flash('Debe agregar al menos 1 crédito.', 'danger')
        return redirect(url_for('admin.resellers'))

    old_balance = r.panel_credits or 0
    r.panel_credits = (r.panel_credits or 0) + amount

    _log_credit_movement(
        r,
        amount,
        f"Top-up de {amount} credito(s) por admin {current_user.username}",
    )

    db.session.commit()
    flash(f"Agregados {amount} créditos a '{r.username}'. Saldo anterior: {old_balance} → Nuevo saldo: {r.panel_credits}", 'success')
    return redirect(url_for('admin.resellers'))


# ──────────────────────────────────────────────────────────
# VPN Users (admin view — all users)
# ──────────────────────────────────────────────────────────

@admin_bp.route('/users')
@admin_required
def users():
    all_users = (
        VpnUser.query
        .options(joinedload(VpnUser.server), joinedload(VpnUser.reseller))
        .filter_by(is_active=True)
        .order_by(VpnUser.created_at.desc())
        .all()
    )
    all_resellers = (
        Reseller.query
        .filter(Reseller.is_active.is_(True), Reseller.note != SYSTEM_ADMIN_RESELLER_NOTE)
        .all()
    )
    all_servers = Server.query.filter_by(is_active=True).all()
    return render_template(
        'admin/users.html',
        users=all_users,
        resellers=all_resellers,
        servers=all_servers,
        package_options=PACKAGE_OPTIONS,
    )


@admin_bp.route('/users/online')
@admin_required
def online_users():
    # Debug mode: ?debug=1 returns raw SSH output to diagnose detection issues
    if request.args.get('debug') == '1':
        servers = Server.query.filter_by(is_active=True).all()
        debug_data = {}
        for server in servers:
            svc = SSHService(server)
            ok, raw, err = svc.debug_online_raw()
            debug_data[server.name] = raw if ok else {'error': err}
        return jsonify({'ok': True, 'debug': debug_data})
    active_users = VpnUser.query.filter_by(is_active=True).all()
    if not active_users:
        return jsonify({'ok': True, 'online': {}})

    users_by_server: dict[int, list[VpnUser]] = {}
    for u in active_users:
        users_by_server.setdefault(u.server_id, []).append(u)

    online_by_user_id: dict[str, int] = {}
    errors: list[str] = []

    for server_id, server_users in users_by_server.items():
        server = db.session.get(Server, server_id)
        if not server:
            continue

        svc = SSHService(server)
        ok, online_map, err = svc.get_online_users()
        if not ok:
            errors.append(f"{server.name}: {err}")
            continue

        normalized = {k.strip().upper(): v for k, v in online_map.items()}
        for u in server_users:
            count = normalized.get(u.username.strip().upper(), 0)
            if count > 0:
                online_by_user_id[str(u.id)] = {
                    'sessions': count,
                    'limit': u.connection_limit,
                }

    return jsonify({'ok': True, 'online': online_by_user_id, 'errors': errors})


@admin_bp.route('/users/create', methods=['POST'])
@admin_required
def create_user():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    package_code = request.form.get('package', '1m')
    limit = request.form.get('limit', 1, type=int)
    reseller_id = request.form.get('reseller_id', type=int)
    server_id = request.form.get('server_id', type=int)
    create_as_admin = request.form.get('create_as_admin') in {'1', 'true', 'on'}

    if create_as_admin:
        reseller_id = None

    if not username or not password or not server_id:
        flash('Todos los campos son obligatorios.', 'danger')
        return redirect(url_for('admin.users'))

    if not VPN_USERNAME_PATTERN.fullmatch(username):
        flash('Formato de usuario invalido. Usa solo MAYUSCULAS con guion intermedio.', 'danger')
        return redirect(url_for('admin.users'))

    server = db.session.get(Server, server_id)
    if not server:
        flash('Servidor inválido.', 'danger')
        return redirect(url_for('admin.users'))

    if reseller_id:
        reseller = db.session.get(Reseller, reseller_id)
        if not reseller or reseller.note == SYSTEM_ADMIN_RESELLER_NOTE:
            flash('Revendedor inválido.', 'danger')
            return redirect(url_for('admin.users'))
    else:
        reseller = _get_or_create_system_reseller(server_id)

    package = _resolve_package(package_code)
    credits_needed = package.get('credits', 0)
    can_charge, charge_msg = _can_charge_credits(reseller, credits_needed)
    if not can_charge:
        flash(charge_msg, 'danger')
        return redirect(url_for('admin.users'))

    if VpnUser.query.filter_by(reseller_id=reseller.id, username=username, is_active=True).first():
        flash(f"Ya existe un usuario activo con ese nombre dentro del propietario asignado: '{username}'.", 'danger')
        return redirect(url_for('admin.users'))

    svc = SSHService(server)
    create_days = package.get('days', 1)
    ok, msg = svc.create_user(username, password, create_days, limit)

    if not ok:
        flash(f'Error al crear usuario: {msg}', 'danger')
        return redirect(url_for('admin.users'))

    expiry_dt = datetime.utcnow() + timedelta(days=create_days)
    if package_code == 'demo_1h':
        expiry_dt = datetime.utcnow() + timedelta(hours=DEMO_MAX_HOURS)

    vu = VpnUser(
        username=username,
        password=password,
        connection_limit=limit,
        expiry_date=expiry_dt,
        reseller_id=reseller.id,
        server_id=server_id,
    )

    if package_code == 'demo_1h':
        sched_ok, sched_msg = svc.schedule_demo_deletion(username, DEMO_MAX_HOURS)
        if not sched_ok:
            flash(f'Advertencia demo: no se pudo programar autoeliminacion en servidor ({sched_msg}).', 'warning')

    if credits_needed > 0 and reseller.note != SYSTEM_ADMIN_RESELLER_NOTE:
        reseller.panel_credits = max(0, (reseller.panel_credits or 0) - credits_needed)
        _log_credit_movement(
            reseller,
            -credits_needed,
            f"Compra paquete {package['label']} para usuario {username} (creado por admin {current_user.username})",
        )

    db.session.add(vu)
    db.session.commit()
    if credits_needed > 0 and reseller.note != SYSTEM_ADMIN_RESELLER_NOTE:
        flash(f"{msg} | Paquete: {package['label']} | Creditos cobrados: {credits_needed}", 'success')
    else:
        flash(f"{msg} | Paquete: {package['label']}", 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/create-demo', methods=['POST'])
@admin_required
def create_demo_user():
    limit = request.form.get('limit', 1, type=int) or 1
    reseller_id = request.form.get('reseller_id', type=int)
    server_id = request.form.get('server_id', type=int)
    create_as_admin = request.form.get('create_as_admin') in {'1', 'true', 'on'}

    if create_as_admin:
        reseller_id = None

    if not server_id:
        flash('Debes seleccionar un servidor para crear un demo.', 'danger')
        return redirect(url_for('admin.users'))

    limit = max(1, limit)

    server = db.session.get(Server, server_id)
    if not server:
        flash('Servidor inválido.', 'danger')
        return redirect(url_for('admin.users'))

    if reseller_id:
        reseller = db.session.get(Reseller, reseller_id)
        if not reseller or reseller.note == SYSTEM_ADMIN_RESELLER_NOTE:
            flash('Revendedor inválido.', 'danger')
            return redirect(url_for('admin.users'))
    else:
        reseller = _get_or_create_system_reseller(server_id)

    svc = SSHService(server)
    created = False
    username = ''
    password = ''
    msg = ''

    for _ in range(12):
        username = _generate_demo_username()
        password = _generate_demo_password(10)

        if VpnUser.query.filter_by(reseller_id=reseller.id, username=username, is_active=True).first():
            continue

        # Linux account expiry uses day granularity; enforce 1h by scheduled deletion.
        ok, msg = svc.create_user(username, password, 1, limit)
        if ok:
            created = True
            break
        if 'ya existe en el servidor' in msg.lower():
            continue
        flash(f'Error al crear usuario demo: {msg}', 'danger')
        return redirect(url_for('admin.users'))

    if not created:
        flash('No fue posible generar un nombre demo disponible. Intenta de nuevo.', 'danger')
        return redirect(url_for('admin.users'))

    vu = VpnUser(
        username=username,
        password=password,
        connection_limit=limit,
        expiry_date=datetime.utcnow() + timedelta(hours=DEMO_MAX_HOURS),
        reseller_id=reseller.id,
        server_id=server_id,
    )
    db.session.add(vu)
    db.session.commit()

    sched_ok, sched_msg = svc.schedule_demo_deletion(username, DEMO_MAX_HOURS)
    owner_label = 'Admin' if reseller.note == SYSTEM_ADMIN_RESELLER_NOTE else reseller.username
    if not sched_ok:
        flash(f'Advertencia demo: no se pudo programar autoeliminacion en servidor ({sched_msg}).', 'warning')
    flash(
        f"Demo creado: usuario '{username}' | clave '{password}' | {DEMO_MAX_HOURS} hora(s) | propietario: {owner_label}.",
        'success',
    )
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id: int):
    u = db.session.get(VpnUser, user_id)
    if not u:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('admin.users'))

    svc = SSHService(u.server)
    ok, msg = svc.delete_user(u.username)
    if ok:
        u.is_active = False
        db.session.commit()
        flash(f"Usuario '{u.username}' eliminado del servidor.", 'success')
    else:
        flash(f"Error al eliminar del servidor: {msg}. Marcado como inactivo.", 'warning')
        u.is_active = False
        db.session.commit()
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/renew', methods=['POST'])
@admin_required
def renew_user(user_id: int):
    u = db.session.get(VpnUser, user_id)
    if not u:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('admin.users'))

    if not u.is_active:
        flash('No es posible renovar un usuario inactivo.', 'danger')
        return redirect(url_for('admin.users'))

    package_code = request.form.get('package', '1m')
    package = _resolve_package(package_code)
    credits_needed = package.get('credits', 0)

    reseller = u.reseller
    can_charge, charge_msg = _can_charge_credits(reseller, credits_needed)
    if not can_charge:
        flash(charge_msg, 'danger')
        return redirect(url_for('admin.users'))

    now = datetime.utcnow()
    if package_code == 'demo_1h':
        renew_hours = package.get('hours', 1)
        base = u.expiry_date if u.expiry_date > now else now
        new_expiry = base + timedelta(hours=renew_hours)
    else:
        renew_days = package.get('days', 30)
        if u.expiry_date > now:
            new_expiry = u.expiry_date + timedelta(days=renew_days)
        else:
            new_expiry = now + timedelta(days=renew_days)

    # El servidor maneja expiracion con granularidad en dias.
    days_from_now = max(1, int(math.ceil((new_expiry - now).total_seconds() / 86400.0)))

    svc = SSHService(u.server)
    ok, msg = svc.change_expiry(u.username, days_from_now)
    if not ok:
        flash(f'Error al renovar usuario en servidor: {msg}', 'danger')
        return redirect(url_for('admin.users'))

    u.expiry_date = new_expiry

    if credits_needed > 0 and reseller.note != SYSTEM_ADMIN_RESELLER_NOTE:
        reseller.panel_credits = max(0, (reseller.panel_credits or 0) - credits_needed)
        _log_credit_movement(
            reseller,
            -credits_needed,
            f"Renovacion de paquete {package['label']} para usuario {u.username} (renovado por admin {current_user.username})",
        )

    db.session.commit()
    flash(f"Usuario '{u.username}' renovado hasta {new_expiry.strftime('%d/%m/%Y %H:%M')}. Paquete: {package['label']}", 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/block', methods=['POST'])
@admin_required
def block_user(user_id: int):
    u = db.session.get(VpnUser, user_id)
    if not u:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('admin.users'))

    svc = SSHService(u.server)
    ok, msg = svc.block_user(u.username)
    if ok:
        u.is_blocked = True
        db.session.commit()
        flash(msg, 'success')
    else:
        flash(f'Error al bloquear usuario: {msg}', 'danger')
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/unblock', methods=['POST'])
@admin_required
def unblock_user(user_id: int):
    u = db.session.get(VpnUser, user_id)
    if not u:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('admin.users'))

    svc = SSHService(u.server)
    ok, msg = svc.unblock_user(u.username)
    if ok:
        u.is_blocked = False
        db.session.commit()
        flash(msg, 'success')
    else:
        flash(f'Error al desbloquear usuario: {msg}', 'danger')
    return redirect(url_for('admin.users'))


# ──────────────────────────────────────────────────────────
# Change password
# ──────────────────────────────────────────────────────────

@admin_bp.route('/users/<int:user_id>/password', methods=['POST'])
@admin_required
def change_password(user_id: int):
    u = db.session.get(VpnUser, user_id)
    if not u:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('admin.users'))

    new_password = request.form.get('password', '')
    svc = SSHService(u.server)
    ok, msg = svc.change_password(u.username, new_password)
    if ok:
        u.password = new_password
        db.session.commit()
        flash(msg, 'success')
    else:
        flash(f'Error: {msg}', 'danger')
    return redirect(url_for('admin.users'))


# ──────────────────────────────────────────────────────────
# Change limit
# ──────────────────────────────────────────────────────────

@admin_bp.route('/users/<int:user_id>/limit', methods=['POST'])
@admin_required
def change_limit(user_id: int):
    u = db.session.get(VpnUser, user_id)
    if not u:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('admin.users'))

    new_limit = request.form.get('limit', type=int)
    if not new_limit or new_limit < 1:
        flash('Límite inválido.', 'danger')
        return redirect(url_for('admin.users'))

    svc = SSHService(u.server)
    ok, msg = svc.change_limit(u.username, new_limit)
    if ok:
        u.connection_limit = new_limit
        db.session.commit()
        flash(msg, 'success')
    else:
        flash(f'Error: {msg}', 'danger')
    return redirect(url_for('admin.users'))


# ──────────────────────────────────────────────────────────
# Backup / Restore
# ──────────────────────────────────────────────────────────

@admin_bp.route('/backup/create', methods=['POST'])
@admin_required
def create_backup():
    try:
        db_path = _sqlite_db_path()
    except ValueError as ex:
        flash(str(ex), 'danger')
        return redirect(url_for('admin.dashboard'))

    if not os.path.isfile(db_path):
        flash('No se encontró la base de datos para generar la copia.', 'danger')
        return redirect(url_for('admin.dashboard'))

    key_path = os.path.join(current_app.instance_path, '.enc_key')

    # Snapshot consistente de SQLite
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as temp_db:
        snapshot_db = temp_db.name

    try:
        src = sqlite3.connect(db_path)
        dst = sqlite3.connect(snapshot_db)
        src.backup(dst)
        dst.close()
        src.close()

        backup_stream = io.BytesIO()
        created_at = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        filename = f"vpnpro-backup-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.zip"
        backup_file_path = os.path.join(_backups_dir(), filename)
        metadata = {
            'app': 'VPNPro Web Panel',
            'created_at_utc': created_at,
            'format': 'vpnpro-backup-v1',
            'files': ['vpnpro.db'] + (['.enc_key'] if os.path.isfile(key_path) else []),
        }

        with zipfile.ZipFile(backup_stream, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(snapshot_db, arcname='vpnpro.db')
            if os.path.isfile(key_path):
                zf.write(key_path, arcname='.enc_key')
            zf.writestr('metadata.json', json.dumps(metadata, ensure_ascii=True, indent=2))

        with open(backup_file_path, 'wb') as fh:
            fh.write(backup_stream.getvalue())

        backup_stream.seek(0)
        return send_file(
            backup_stream,
            as_attachment=True,
            download_name=filename,
            mimetype='application/zip',
        )
    finally:
        if os.path.exists(snapshot_db):
            os.remove(snapshot_db)


@admin_bp.route('/backup/restore', methods=['POST'])
@admin_required
def restore_backup():
    uploaded = request.files.get('backup_file')
    if not uploaded or not uploaded.filename:
        flash('Selecciona un archivo de copia (.zip).', 'danger')
        return redirect(url_for('admin.dashboard'))

    if not uploaded.filename.lower().endswith('.zip'):
        flash('Formato inválido. Debe ser un archivo .zip generado por el panel.', 'danger')
        return redirect(url_for('admin.dashboard'))

    try:
        db_path = _sqlite_db_path()
    except ValueError as ex:
        flash(str(ex), 'danger')
        return redirect(url_for('admin.dashboard'))

    key_path = os.path.join(current_app.instance_path, '.enc_key')
    os.makedirs(current_app.instance_path, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, 'restore.zip')
        db_tmp = os.path.join(tmpdir, 'vpnpro.db')
        key_tmp = os.path.join(tmpdir, '.enc_key')
        uploaded.save(zip_path)

        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                names = zf.namelist()
                db_member = _find_zip_member(names, 'vpnpro.db')
                if not db_member:
                    flash('El ZIP no contiene vpnpro.db. Copia inválida.', 'danger')
                    return redirect(url_for('admin.dashboard'))

                with zf.open(db_member, 'r') as src, open(db_tmp, 'wb') as dst:
                    shutil.copyfileobj(src, dst)

                key_member = _find_zip_member(names, '.enc_key')
                if key_member:
                    with zf.open(key_member, 'r') as src, open(key_tmp, 'wb') as dst:
                        shutil.copyfileobj(src, dst)

            # Validar integridad de SQLite antes de reemplazar
            conn = sqlite3.connect(db_tmp)
            integrity = conn.execute('PRAGMA integrity_check;').fetchone()[0]
            conn.close()
            if integrity.lower() != 'ok':
                flash('La copia está dañada (integrity_check falló).', 'danger')
                return redirect(url_for('admin.dashboard'))

            db.session.remove()
            db.engine.dispose()

            db_backup = db_path + '.pre-restore.bak'
            key_backup = key_path + '.pre-restore.bak'
            if os.path.isfile(db_path):
                shutil.copy2(db_path, db_backup)
            if os.path.isfile(key_path):
                shutil.copy2(key_path, key_backup)

            shutil.copy2(db_tmp, db_path)
            if os.path.isfile(key_tmp):
                shutil.copy2(key_tmp, key_path)
                with open(key_path, 'rb') as fh:
                    current_app.config['ENCRYPTION_KEY'] = fh.read().strip()

            flash('Copia restaurada correctamente. Se recomienda reiniciar el servicio del panel.', 'success')
            return redirect(url_for('admin.dashboard'))

        except zipfile.BadZipFile:
            flash('El archivo subido no es un ZIP válido.', 'danger')
            return redirect(url_for('admin.dashboard'))
        except Exception as ex:
            flash(f'Error al restaurar copia: {ex}', 'danger')
            return redirect(url_for('admin.dashboard'))


@admin_bp.route('/backup/download/<path:filename>', methods=['GET'])
@admin_required
def download_backup(filename: str):
    full_path = _safe_backup_file(filename)
    if not full_path:
        flash('Archivo de copia no encontrado.', 'danger')
        return redirect(url_for('admin.dashboard'))
    return send_file(full_path, as_attachment=True, download_name=os.path.basename(full_path))


@admin_bp.route('/backup/delete/<path:filename>', methods=['POST'])
@admin_required
def delete_backup(filename: str):
    full_path = _safe_backup_file(filename)
    if not full_path:
        flash('Archivo de copia no encontrado.', 'danger')
        return redirect(url_for('admin.dashboard'))

    os.remove(full_path)
    flash('Copia eliminada del historial.', 'success')
    return redirect(url_for('admin.dashboard'))


@admin_bp.route('/panel/restart', methods=['POST'])
@admin_required
def restart_panel_service():
    cmd = 'sleep 1; systemctl restart vpnpro-web.service >/dev/null 2>&1'
    try:
        subprocess.Popen(['sh', '-c', cmd])
        flash('Reinicio del panel solicitado. Espera unos segundos y recarga la página.', 'success')
    except Exception as ex:
        flash(f'No se pudo solicitar el reinicio del panel: {ex}', 'danger')
    return redirect(url_for('admin.dashboard'))
