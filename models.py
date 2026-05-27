from datetime import datetime, timedelta, timezone

PH_TZ = timezone(timedelta(hours=8))


def now_ph():
    """Return current Philippine Time (UTC+8)."""
    return datetime.now(PH_TZ)

from werkzeug.security import generate_password_hash
from db import execute, DB_INTEGRITY_ERRORS


def normalize_ip(ip: str) -> str:
    """Normalize IP address for consistent storage and comparison."""
    if not ip:
        return "127.0.0.1"
    ip = ip.strip().lower() if isinstance(ip, str) else str(ip).strip().lower()
    # Remove port if present (handle cases like "192.168.1.1:8080")
    if ':' in ip and not ip.startswith('['):  # IPv4 with port
        ip = ip.split(':')[0]
    elif ip.startswith('[') and ']:' in ip:  # IPv6 with port like [::1]:8080
        ip = ip.split(']:')[0].strip('[]')
    return ip


def _scalar(row, key=None):
    if not row:
        return 0
    if key is None:
        try:
            return row[0]
        except Exception:
            return next(iter(row.values()), 0)
    try:
        return row[key]
    except Exception:
        try:
            return row[0]
        except Exception:
            return None


def get_user_by_username(username):
    return execute("SELECT * FROM users WHERE username = ?", (username,), fetchone=True)


def get_user_by_id(user_id):
    return execute("SELECT * FROM users WHERE id = ?", (user_id,), fetchone=True)


def create_user(username, password_hash, role="user", approved=False):
    execute(
        "INSERT INTO users (username, password_hash, role, approved, created_at) VALUES (?, ?, ?, ?, ?)",
        (username, password_hash, role, bool(approved), now_ph()),
        commit=True,
    )


def get_allowed_ip(ip):
    ip = normalize_ip(ip)
    return execute("SELECT * FROM allowed_ips WHERE ip = ?", (ip,), fetchone=True)


def list_allowed_ips():
    return execute("SELECT * FROM allowed_ips ORDER BY created_at DESC", fetchall=True)


def create_allowed_ip(ip, label=None, approved_by="system"):
    ip = normalize_ip(ip)
    existing = get_allowed_ip(ip)
    if existing:
        return existing
    now = now_ph()
    execute(
        "INSERT INTO allowed_ips (ip, label, active, approved_by, approved_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (ip, label or "approved", True, approved_by, now, now),
        commit=True,
    )
    return get_allowed_ip(ip)
