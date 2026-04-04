from __future__ import annotations

from datetime import datetime, timedelta
from functools import wraps
import math
import re
import secrets
import string

from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_required, current_user, logout_user

from models import db, Admin, Reseller, VpnUser, CreditMovement
from services.ssh_service import SSHService

reseller_bp = Blueprint('reseller', __name__)
VPN_USERNAME_PATTERN = re.compile(r'^[A-ZÑ]+-[A-ZÑ]+$')
DEMO_MAX_HOURS = 1
DEMO_MIN_CREDITS = 5
PACKAGE_OPTIONS = {
    'demo_1h': {'label': 'Demo 1 hora', 'hours': 1, 'months': 0, 'credits': 0},
    '1m': {'label': '1 Mes', 'days': 30, 'months': 1, 'credits': 1},
    '3m': {'label': '3 Meses', 'days': 90, 'months': 3, 'credits': 3},
    '6m': {'label': '6 Meses', 'days': 180, 'months': 6, 'credits': 6},
    '12m': {'label': '12 Meses', 'days': 360, 'months': 12, 'credits': 12},
}


def _generate_demo_username() -> str:
    suffix = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(4))
    return f'DEMO-{suffix}'


def _generate_demo_password(length: int = 10) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def _resolve_package(package_code: str) -> dict:
    return PACKAGE_OPTIONS.get(package_code, PACKAGE_OPTIONS['1m'])


def reseller_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not isinstance(current_user, Reseller):
            flash('Acceso restringido a revendedores.', 'danger')
            return redirect(url_for('auth.login'))
        if not current_user.is_active:
            flash('Tu cuenta está desactivada.', 'danger')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return login_required(decorated)


# ──────────────────────────────────────────────────────────
# Dashboard
# ──────────────────────────────────────────────────────────

@reseller_bp.route('/')
@reseller_required
def dashboard():
    r: Reseller = current_user
    now = datetime.utcnow()
    total_count = VpnUser.query.filter_by(reseller_id=r.id, is_active=True).count()
    expired_count = (
        VpnUser.query
        .filter(
            VpnUser.reseller_id == r.id,
            VpnUser.is_active.is_(True),
            VpnUser.expiry_date < now,
        )
        .count()
    )
    active_count = max(0, total_count - expired_count)

    svc = SSHService(r.server)
    ok, server_info, _ = svc.get_server_info()
    credit_logs = (
        CreditMovement.query
        .filter_by(reseller_id=r.id)
        .order_by(CreditMovement.created_at.desc())
        .limit(12)
        .all()
    )

    return render_template(
        'reseller/dashboard.html',
        reseller=r,
            server=r.server,
        active_count=active_count,
        expired_count=expired_count,
        total_count=total_count,
        server_info=server_info if ok else {},
        credit_logs=credit_logs,
    )


@reseller_bp.route('/account', methods=['POST'])
@reseller_required
def update_account():
    r: Reseller = current_user
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not r.check_password(current_password):
        flash('La contraseña actual no es correcta.', 'danger')
        return redirect(url_for('reseller.dashboard'))

    changed = False
    password_changed = False

    if new_password:
        if len(new_password) < 6:
            flash('La nueva contraseña debe tener al menos 6 caracteres.', 'danger')
            return redirect(url_for('reseller.dashboard'))
        if new_password != confirm_password:
            flash('La confirmación de contraseña no coincide.', 'danger')
            return redirect(url_for('reseller.dashboard'))
        r.set_password(new_password)
        password_changed = True
        changed = True

    if not changed:
        flash('No se detectaron cambios para guardar.', 'warning')
        return redirect(url_for('reseller.dashboard'))

    db.session.commit()
    if password_changed:
        logout_user()
        flash('Contraseña actualizada. Inicia sesión nuevamente.', 'success')
        return redirect(url_for('auth.login'))

    flash('Credenciales actualizadas.', 'success')
    return redirect(url_for('reseller.dashboard'))


# ──────────────────────────────────────────────────────────
# VPN Users — list
# ──────────────────────────────────────────────────────────

@reseller_bp.route('/users')
@reseller_required
def users():

    r: Reseller = current_user
    user_list = (
        VpnUser.query
        .filter_by(reseller_id=r.id, is_active=True)
        .order_by(VpnUser.created_at.desc())
        .all()
    )
    server = r.server  # Ensure server relationship is loaded
    return render_template(
        'reseller/users.html',
        reseller=r,
        server=server,
        users=user_list,
        package_options=PACKAGE_OPTIONS,
    )

# ──────────────────────────────────────────────────────────
# Create user
# ──────────────────────────────────────────────────────────

@reseller_bp.route('/users/create', methods=['POST'])
@reseller_required
def create_user():
    r: Reseller = current_user

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    package_code = request.form.get('package', '1m')
    limit = request.form.get('limit', 1, type=int)

    if not username or not password:
        flash('Todos los campos son obligatorios.', 'danger')
        return redirect(url_for('reseller.users'))

    if not VPN_USERNAME_PATTERN.fullmatch(username):
        flash('Formato de usuario invalido. Usa solo MAYUSCULAS con guion intermedio.', 'danger')
        return redirect(url_for('reseller.users'))

    if int(limit) > r.max_connections:
        flash(
            f'No, no puedes crear este usuario con {limit} conexión(es). El administrador te permite hasta {r.max_connections} conexión(es) por usuario.',
            'danger',
        )
        return redirect(url_for('reseller.users'))

    # Check username is not already in DB for this reseller
    if VpnUser.query.filter_by(reseller_id=r.id, username=username, is_active=True).first():
        flash(f"Ya tienes un usuario activo con ese nombre: '{username}'.", 'danger')
        return redirect(url_for('reseller.users'))

    package = _resolve_package(package_code)
    credits_needed = package.get('credits', 0)
    if package_code == 'demo_1h' and (r.panel_credits or 0) < DEMO_MIN_CREDITS:
        flash(
            f'Para crear demos necesitas al menos {DEMO_MIN_CREDITS} créditos disponibles. Tienes {r.panel_credits or 0}.',
            'danger',
        )
        return redirect(url_for('reseller.users'))

    if credits_needed > 0 and (r.panel_credits or 0) < credits_needed:
        flash(f'Creditos insuficientes. Requiere {credits_needed} y tienes {r.panel_credits or 0}.', 'danger')
        return redirect(url_for('reseller.users'))

    svc = SSHService(r.server)
    create_days = package.get('days', 1)
    ok, msg = svc.create_user(username, password, create_days, limit)

    if not ok:
        flash(f'Error al crear usuario: {msg}', 'danger')
        return redirect(url_for('reseller.users'))

    expiry_dt = datetime.utcnow() + timedelta(days=create_days)
    if package_code == 'demo_1h':
        expiry_dt = datetime.utcnow() + timedelta(hours=DEMO_MAX_HOURS)

    vu = VpnUser(
        username=username,
        password=password,
        connection_limit=limit,
        expiry_date=expiry_dt,
        reseller_id=r.id,
        server_id=r.server_id,
    )

    if package_code == 'demo_1h':
        sched_ok, sched_msg = svc.schedule_demo_deletion(username, DEMO_MAX_HOURS)
        if not sched_ok:
            flash(f'Advertencia demo: no se pudo programar autoeliminacion en servidor ({sched_msg}).', 'warning')

    if credits_needed > 0:
        r.panel_credits = max(0, (r.panel_credits or 0) - credits_needed)
        db.session.add(
            CreditMovement(
                reseller_id=r.id,
                delta=-credits_needed,
                balance_after=r.panel_credits or 0,
                reason=f"Compra paquete {package['label']} para usuario {username}",
            )
        )

    db.session.add(vu)
    db.session.commit()
    if credits_needed > 0:
        flash(f"{msg} | Paquete: {package['label']} | Creditos cobrados: {credits_needed}", 'success')
    else:
        flash(f"{msg} | Paquete: {package['label']}", 'success')
    return redirect(url_for('reseller.users'))


@reseller_bp.route('/users/create-demo', methods=['POST'])
@reseller_required
def create_demo_user():
    r: Reseller = current_user
    limit = request.form.get('limit', 1, type=int) or 1

    limit = max(1, limit)

    if int(limit) > r.max_connections:
        flash(
            f'No, no puedes crear este demo con {limit} conexión(es). El administrador te permite hasta {r.max_connections} conexión(es) por usuario.',
            'danger',
        )
        return redirect(url_for('reseller.users'))

    if (r.panel_credits or 0) < DEMO_MIN_CREDITS:
        flash(
            f'Para crear demos necesitas al menos {DEMO_MIN_CREDITS} créditos disponibles. Tienes {r.panel_credits or 0}.',
            'danger',
        )
        return redirect(url_for('reseller.users'))

    svc = SSHService(r.server)
    created = False
    username = ''
    password = ''
    msg = ''

    for _ in range(12):
        username = _generate_demo_username()
        password = _generate_demo_password(10)

        if VpnUser.query.filter_by(reseller_id=r.id, username=username, is_active=True).first():
            continue

        # Linux account expiry uses day granularity; enforce 1h by scheduled deletion.
        ok, msg = svc.create_user(username, password, 1, limit)
        if ok:
            created = True
            break
        if 'ya existe en el servidor' in msg.lower():
            continue
        flash(f'Error al crear usuario demo: {msg}', 'danger')
        return redirect(url_for('reseller.users'))

    if not created:
        flash('No fue posible generar un nombre demo disponible. Intenta de nuevo.', 'danger')
        return redirect(url_for('reseller.users'))

    vu = VpnUser(
        username=username,
        password=password,
        connection_limit=limit,
        expiry_date=datetime.utcnow() + timedelta(hours=DEMO_MAX_HOURS),
        reseller_id=r.id,
        server_id=r.server_id,
    )
    db.session.add(vu)
    db.session.commit()

    sched_ok, sched_msg = svc.schedule_demo_deletion(username, DEMO_MAX_HOURS)
    if not sched_ok:
        flash(f'Advertencia demo: no se pudo programar autoeliminacion en servidor ({sched_msg}).', 'warning')
    flash(f"Demo creado: usuario '{username}' | clave '{password}' | {DEMO_MAX_HOURS} hora(s).", 'success')
    return redirect(url_for('reseller.users'))


# ──────────────────────────────────────────────────────────
# Delete user
# ──────────────────────────────────────────────────────────

@reseller_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@reseller_required
def delete_user(user_id: int):
    r: Reseller = current_user
    u = db.session.get(VpnUser, user_id)
    if not u or u.reseller_id != r.id:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('reseller.users'))

    svc = SSHService(r.server)
    ok, msg = svc.delete_user(u.username)
    u.is_active = False
    db.session.commit()
    if ok:
        flash(f"Usuario '{u.username}' eliminado.", 'success')
    else:
        flash(f"Usuario marcado como inactivo. Error en servidor: {msg}", 'warning')
    return redirect(url_for('reseller.users'))


# ──────────────────────────────────────────────────────────
# Change password
# ──────────────────────────────────────────────────────────

@reseller_bp.route('/users/<int:user_id>/password', methods=['POST'])
@reseller_required
def change_password(user_id: int):
    r: Reseller = current_user
    u = db.session.get(VpnUser, user_id)
    if not u or u.reseller_id != r.id:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('reseller.users'))

    new_password = request.form.get('password', '')
    svc = SSHService(r.server)
    ok, msg = svc.change_password(u.username, new_password)
    if ok:
        u.password = new_password
        db.session.commit()
        flash(msg, 'success')
    else:
        flash(f'Error: {msg}', 'danger')
    return redirect(url_for('reseller.users'))


# ──────────────────────────────────────────────────────────
# Change limit
# ──────────────────────────────────────────────────────────

@reseller_bp.route('/users/<int:user_id>/limit', methods=['POST'])
@reseller_required
def change_limit(user_id: int):
    r: Reseller = current_user
    u = db.session.get(VpnUser, user_id)
    if not u or u.reseller_id != r.id:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('reseller.users'))

    new_limit = request.form.get('limit', type=int)
    if not new_limit or new_limit < 1:
        flash('Límite inválido.', 'danger')
        return redirect(url_for('reseller.users'))

    if new_limit > r.max_connections:
        flash(
            f'No, no puedes aumentar este límite a {new_limit}. El administrador te permite hasta {r.max_connections} conexión(es) por usuario.',
            'danger',
        )
        return redirect(url_for('reseller.users'))

    svc = SSHService(r.server)
    ok, msg = svc.change_limit(u.username, new_limit)
    if ok:
        u.connection_limit = new_limit
        db.session.commit()
        flash(msg, 'success')
    else:
        flash(f'Error: {msg}', 'danger')
    return redirect(url_for('reseller.users'))


# ──────────────────────────────────────────────────────────
# Change expiry
# ──────────────────────────────────────────────────────────

@reseller_bp.route('/users/<int:user_id>/expiry', methods=['POST'])
@reseller_required
def change_expiry(user_id: int):
    r: Reseller = current_user
    u = db.session.get(VpnUser, user_id)
    if not u or u.reseller_id != r.id:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('reseller.users'))

    package_code = request.form.get('package', '1m')
    package = _resolve_package(package_code)
    credits_needed = package.get('credits', 0)

    if package_code == 'demo_1h' and (r.panel_credits or 0) < DEMO_MIN_CREDITS:
        flash(
            f'Para renovar demos necesitas al menos {DEMO_MIN_CREDITS} créditos disponibles. Tienes {r.panel_credits or 0}.',
            'danger',
        )
        return redirect(url_for('reseller.users'))

    if credits_needed > 0 and (r.panel_credits or 0) < credits_needed:
        flash(f'Creditos insuficientes. Requiere {credits_needed} y tienes {r.panel_credits or 0}.', 'danger')
        return redirect(url_for('reseller.users'))

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

    days_from_now = max(1, int(math.ceil((new_expiry - now).total_seconds() / 86400.0)))

    svc = SSHService(r.server)
    ok, msg = svc.change_expiry(u.username, days_from_now)
    if ok:
        u.expiry_date = new_expiry
        if credits_needed > 0:
            r.panel_credits = max(0, (r.panel_credits or 0) - credits_needed)
            db.session.add(
                CreditMovement(
                    reseller_id=r.id,
                    delta=-credits_needed,
                    balance_after=r.panel_credits or 0,
                    reason=f"Renovacion paquete {package['label']} para usuario {u.username}",
                )
            )
        db.session.commit()
        if credits_needed > 0:
            flash(
                f"Usuario '{u.username}' renovado hasta {new_expiry.strftime('%d/%m/%Y %H:%M')}. "
                f"Paquete: {package['label']} | Creditos cobrados: {credits_needed}",
                'success',
            )
        else:
            flash(
                f"Usuario '{u.username}' renovado hasta {new_expiry.strftime('%d/%m/%Y %H:%M')}. "
                f"Paquete: {package['label']}",
                'success',
            )
    else:
        flash(f'Error al renovar usuario: {msg}', 'danger')
    return redirect(url_for('reseller.users'))


@reseller_bp.route('/users/<int:user_id>/block', methods=['POST'])
@reseller_required
def block_user(user_id: int):
    r: Reseller = current_user
    u = db.session.get(VpnUser, user_id)
    if not u or u.reseller_id != r.id:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('reseller.users'))

    svc = SSHService(r.server)
    ok, msg = svc.block_user(u.username)
    if ok:
        u.is_blocked = True
        db.session.commit()
        flash(msg, 'success')
    else:
        flash(f'Error: {msg}', 'danger')
    return redirect(url_for('reseller.users'))


@reseller_bp.route('/users/<int:user_id>/unblock', methods=['POST'])
@reseller_required
def unblock_user(user_id: int):
    r: Reseller = current_user
    u = db.session.get(VpnUser, user_id)
    if not u or u.reseller_id != r.id:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('reseller.users'))

    svc = SSHService(r.server)
    ok, msg = svc.unblock_user(u.username)
    if ok:
        u.is_blocked = False
        db.session.commit()
        flash(msg, 'success')
    else:
        flash(f'Error: {msg}', 'danger')
    return redirect(url_for('reseller.users'))


# ──────────────────────────────────────────────────────────
# Online users (AJAX)
# ──────────────────────────────────────────────────────────

@reseller_bp.route('/users/online')
@reseller_required
def online_users():
    r: Reseller = current_user
    svc = SSHService(r.server)
    ok, online_map, err = svc.get_online_users()
    if not ok:
        return jsonify({'ok': False, 'msg': err, 'online': {}})

    # Filter to only show this reseller's users
    limit_map = {u.username.strip().upper(): u.connection_limit for u in r.vpn_users if u.is_active}
    my_usernames = set(limit_map.keys())
    normalized_online = {k.strip().upper(): v for k, v in online_map.items()}
    filtered = {
        k: {'sessions': v, 'limit': limit_map.get(k, '?')}
        for k, v in normalized_online.items() if k in my_usernames
    }
    return jsonify({'ok': True, 'online': filtered})
