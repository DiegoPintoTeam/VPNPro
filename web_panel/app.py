import os
import threading
import time

from flask import Flask, redirect, url_for
from flask_login import LoginManager, current_user
from sqlalchemy import text
from models import db, Admin, Reseller, Server
from config import Config


def _start_auto_sync_worker(app: Flask) -> None:
    if not app.config.get('AUTO_SYNC_ENABLED', True):
        app.logger.info('Auto-sync deshabilitado por configuracion.')
        return

    if app.extensions.get('auto_sync_worker_started'):
        return

    # Evita doble worker cuando se usa recarga de Werkzeug en desarrollo.
    if app.debug and os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        return

    interval_min = max(1, int(app.config.get('AUTO_SYNC_INTERVAL_MINUTES', 30)))
    app.extensions['auto_sync_worker_started'] = True

    def _worker() -> None:
        from routes.admin import _sync_server_users_data

        app.logger.info('Auto-sync iniciado cada %s minuto(s).', interval_min)
        while True:
            time.sleep(interval_min * 60)
            try:
                with app.app_context():
                    servers = Server.query.filter_by(is_active=True).all()
                    if not servers:
                        continue

                    ok_servers = 0
                    fail_servers = 0
                    total_created = 0
                    total_updated = 0
                    total_reactivated = 0
                    total_deactivated = 0

                    for server in servers:
                        ok, stats, err = _sync_server_users_data(server)
                        if not ok:
                            fail_servers += 1
                            app.logger.warning(
                                'Auto-sync fallo en servidor %s (%s): %s',
                                server.name,
                                server.id,
                                err,
                            )
                            continue

                        ok_servers += 1
                        total_created += stats['created']
                        total_updated += stats['updated']
                        total_reactivated += stats['reactivated']
                        total_deactivated += stats['deactivated']

                    db.session.commit()
                    app.logger.info(
                        (
                            'Auto-sync completado: %s ok, %s con error | '
                            'nuevos=%s, actualizados=%s, reactivados=%s, desactivados=%s'
                        ),
                        ok_servers,
                        fail_servers,
                        total_created,
                        total_updated,
                        total_reactivated,
                        total_deactivated,
                    )
            except Exception:
                with app.app_context():
                    db.session.rollback()
                app.logger.exception('Auto-sync error inesperado')

    thread = threading.Thread(target=_worker, name='vpnpro-auto-sync', daemon=True)
    thread.start()


def create_app() -> Flask:
    app = Flask(__name__, instance_path=Config.INSTANCE_DIR)
    app.config.from_object(Config)

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Por favor inicia sesión para acceder.'
    login_manager.login_message_category = 'warning'

    @login_manager.user_loader
    def load_user(user_id: str):
        if user_id.startswith('admin:'):
            return db.session.get(Admin, int(user_id.split(':')[1]))
        if user_id.startswith('reseller:'):
            return db.session.get(Reseller, int(user_id.split(':')[1]))
        return None

    from routes.auth import auth_bp
    from routes.admin import admin_bp
    from routes.reseller import reseller_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(reseller_bp, url_prefix='/reseller')

    @app.route('/')
    def index():
        if current_user.is_authenticated:
            if isinstance(current_user, Admin):
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('reseller.dashboard'))
        return redirect(url_for('auth.login'))

    with app.app_context():
        os.makedirs(app.instance_path, exist_ok=True)
        db.create_all()

        # Lightweight runtime migration for existing SQLite deployments.
        cols = db.session.execute(text("PRAGMA table_info(resellers)")).fetchall()
        col_names = {c[1] for c in cols}
        if 'panel_credits' not in col_names:
            db.session.execute(text("ALTER TABLE resellers ADD COLUMN panel_credits INTEGER DEFAULT 0"))
            db.session.commit()
        
        if 'max_connections' not in col_names:
            db.session.execute(text("ALTER TABLE resellers ADD COLUMN max_connections INTEGER DEFAULT 0"))
            db.session.commit()

        admin_cols = db.session.execute(text("PRAGMA table_info(admins)")).fetchall()
        admin_col_names = {c[1] for c in admin_cols}
        if 'max_connections' not in admin_col_names:
            db.session.execute(text("ALTER TABLE admins ADD COLUMN max_connections INTEGER DEFAULT 0"))
            db.session.commit()

        user_cols = db.session.execute(text("PRAGMA table_info(vpn_users)")).fetchall()
        user_col_names = {c[1] for c in user_cols}
        if 'is_blocked' not in user_col_names:
            db.session.execute(text("ALTER TABLE vpn_users ADD COLUMN is_blocked INTEGER DEFAULT 0"))
            db.session.commit()

        # Ensure panel access credentials requested by operator.
        desired_username = 'VPNPro'
        desired_password = '123456'
        target_admin = Admin.query.filter_by(username=desired_username).first()

        if not target_admin:
            target_admin = Admin.query.first()
            if not target_admin:
                target_admin = Admin(username=desired_username)
                db.session.add(target_admin)
            else:
                target_admin.username = desired_username

        target_admin.set_password(desired_password)
        db.session.commit()
        print('[*] Credenciales admin activas → usuario: VPNPro | clave: 123456')

    _start_auto_sync_worker(app)

    return app


if __name__ == '__main__':
    application = create_app()
    application.run(host='0.0.0.0', port=application.config.get('WEB_PANEL_PORT', 80), debug=False)
