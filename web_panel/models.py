from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from datetime import datetime
from flask import current_app

db = SQLAlchemy()


class Admin(UserMixin, db.Model):
    __tablename__ = 'admins'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    max_connections = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    role = 'admin'

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def get_id(self) -> str:
        return f"admin:{self.id}"


class Server(db.Model):
    __tablename__ = 'servers'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    port = db.Column(db.Integer, default=22)
    ssh_user = db.Column(db.String(50), default='root')
    _ssh_password = db.Column('ssh_password', db.String(512), nullable=False)
    description = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    resellers = db.relationship('Reseller', backref='server', lazy=True)
    vpn_users = db.relationship('VpnUser', backref='server', lazy=True)

    def set_ssh_password(self, password: str) -> None:
        key = current_app.config['ENCRYPTION_KEY']
        f = Fernet(key)
        self._ssh_password = f.encrypt(password.encode()).decode()

    def get_ssh_password(self) -> str:
        key = current_app.config['ENCRYPTION_KEY']
        f = Fernet(key)
        return f.decrypt(self._ssh_password.encode()).decode()

    ssh_password = property(get_ssh_password, set_ssh_password)


class Reseller(UserMixin, db.Model):
    __tablename__ = 'resellers'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(100))
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    max_connections = db.Column(db.Integer, default=0)
    panel_credits = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    note = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    vpn_users = db.relationship('VpnUser', backref='reseller', lazy=True)
    credit_movements = db.relationship('CreditMovement', backref='reseller', lazy=True)

    role = 'reseller'

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def get_id(self) -> str:
        return f"reseller:{self.id}"

    @property
    def active_users_count(self) -> int:
        return len([u for u in self.vpn_users if u.is_active])

    @property
    def total_connections_in_use(self) -> int:
        return sum(u.connection_limit for u in self.vpn_users if u.is_active)


class VpnUser(db.Model):
    __tablename__ = 'vpn_users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    connection_limit = db.Column(db.Integer, default=1)
    expiry_date = db.Column(db.DateTime, nullable=False)
    reseller_id = db.Column(db.Integer, db.ForeignKey('resellers.id'), nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_blocked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expiry_date

    @property
    def days_remaining(self) -> int:
        delta = self.expiry_date - datetime.utcnow()
        return max(0, delta.days)


class CreditMovement(db.Model):
    __tablename__ = 'credit_movements'

    id = db.Column(db.Integer, primary_key=True)
    reseller_id = db.Column(db.Integer, db.ForeignKey('resellers.id'), nullable=False)
    delta = db.Column(db.Integer, nullable=False)  # negative: charge, positive: top-up
    balance_after = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
