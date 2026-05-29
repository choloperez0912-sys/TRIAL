from datetime import datetime, timedelta, timezone

PH_TZ = timezone(timedelta(hours=8))


def now_ph():
    """Return current UTC time (stored as naive UTC, converted to PHT on display)."""
    return datetime.utcnow()
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
        "INSERT INTO users (username, password_hash, role, approved, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
        (username, password_hash, role, bool(approved)),
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


def disable_allowed_ip(ip):
    ip = normalize_ip(ip)
    execute(
        "UPDATE allowed_ips SET active = false WHERE ip = ?", (ip,), commit=True
    )


def get_blocked_ip(ip):
    ip = normalize_ip(ip)
    return execute("SELECT * FROM blocked_ips WHERE ip = ?", (ip,), fetchone=True)


def list_blocked_ips():
    return execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC", fetchall=True)


def block_ip(ip, reason, blocked_by="system"):
    ip = normalize_ip(ip)
    existing = get_blocked_ip(ip)
    if existing:
        execute(
            "UPDATE blocked_ips SET active = true, reason = ?, blocked_by = ?, blocked_at = ? WHERE ip = ?",
            (reason, blocked_by, now_ph(), ip),
            commit=True,
        )
    else:
        execute(
            "INSERT INTO blocked_ips (ip, reason, active, blocked_by, blocked_at) VALUES (?, ?, ?, ?, ?)",
            (ip, reason, True, blocked_by, now_ph()),
            commit=True,
        )


def unblock_ip(ip):
    ip = normalize_ip(ip)
    execute(
        "UPDATE blocked_ips SET active = false WHERE ip = ?", (ip,), commit=True
    )


def create_login_request(username, ip, device_info=None):
    ip = normalize_ip(ip)
    existing = execute(
        "SELECT * FROM login_requests WHERE ip = ? AND username = ? AND status = 'pending'", (ip, username), fetchone=True
    )
    if existing:
        return existing
    execute(
        "INSERT INTO login_requests (username, ip, device_info, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (username, ip, device_info or "Unknown device", "pending", now_ph(), now_ph()),
        commit=True,
    )
    return execute(
        "SELECT * FROM login_requests WHERE ip = ? AND username = ? ORDER BY created_at DESC LIMIT 1",
        (ip, username),
        fetchone=True,
    )


def list_login_requests(status="pending"):
    return execute(
        "SELECT * FROM login_requests WHERE status = ? ORDER BY created_at DESC", (status,), fetchall=True
    )


def update_login_request(request_id, status, admin_notes=None):
    execute(
        "UPDATE login_requests SET status = ?, admin_notes = ?, updated_at = ? WHERE id = ?",
        (status, admin_notes or "", now_ph(), request_id),
        commit=True,
    )


def create_notification(title, message, level="info", target_role="admin"):
    execute(
        "INSERT INTO notifications (title, message, level, target_role, is_read, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (title, message, level, target_role, False, now_ph()),
        commit=True,
    )


def list_notifications(target_role="admin", only_unread=False):
    query = "SELECT * FROM notifications WHERE target_role = ?"
    params = [target_role]
    if only_unread:
        query += " AND is_read = false"
    query += " ORDER BY created_at DESC"
    return execute(query, params, fetchall=True)


def mark_notification_read(notification_id):
    execute(
        "UPDATE notifications SET is_read = true WHERE id = ?", (notification_id,), commit=True
    )


def record_log(user_id, username, ip, event, category="system", success=False):
    ip = normalize_ip(ip)
    execute(
        "INSERT INTO logs (user_id, username, ip, event, category, success, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, username, ip, event, category, bool(success), now_ph()),
        commit=True,
    )


def list_recent_logs(limit=50):
    return execute(
        "SELECT * FROM logs ORDER BY created_at DESC LIMIT ?", (limit,), fetchall=True
    )


def count_recent_failed_attempts(ip, window_minutes=15):
    ip = normalize_ip(ip)
    row = execute(
        "SELECT COUNT(*) AS total FROM logs WHERE ip = ? AND event = ? AND created_at >= ?",
        (ip, "Failed authentication", now_ph() - timedelta(minutes=window_minutes)),
        fetchone=True,
    )
    return _scalar(row)


def fetch_dashboard_metrics():
    metrics = {}
    metrics["total_users"] = _scalar(execute("SELECT COUNT(*) AS total FROM users", fetchone=True)) or 0
    metrics["pending_requests"] = _scalar(execute("SELECT COUNT(*) AS total FROM login_requests WHERE status = 'pending'", fetchone=True)) or 0
    metrics["blocked_ips"] = _scalar(execute("SELECT COUNT(*) AS total FROM blocked_ips WHERE active = true", fetchone=True)) or 0
    metrics["unread_notifications"] = _scalar(
        execute("SELECT COUNT(*) AS total FROM notifications WHERE target_role = ? AND is_read = false", ("admin",), fetchone=True)
    ) or 0
    metrics["recent_security_events"] = _scalar(
        execute("SELECT COUNT(*) AS total FROM logs WHERE category = 'security' AND created_at >= ?", (now_ph() - timedelta(hours=24),), fetchone=True)
    ) or 0
    return metrics


def get_system_setting(key, default=None):
    row = execute("SELECT value FROM system_settings WHERE key = ?", (key,), fetchone=True)
    return row["value"] if row else default


def set_system_setting(key, value):
    existing = execute("SELECT 1 FROM system_settings WHERE key = ?", (key,), fetchone=True)
    if existing:
        execute(
            "UPDATE system_settings SET value = ? WHERE key = ?", (value, key), commit=True
        )
    else:
        execute(
            "INSERT INTO system_settings (key, value) VALUES (?, ?)", (key, value), commit=True
        )


def ensure_admin_user(admin_username, admin_password):
    if not admin_username or not admin_password:
        return
    try:
        admin = execute("SELECT * FROM users WHERE username = ?", (admin_username,), fetchone=True)
        if not admin:
            password_hash = generate_password_hash(admin_password)
            try:
                create_user(admin_username, password_hash, role="admin", approved=True)
            except DB_INTEGRITY_ERRORS:
                pass
    except Exception:
        pass


# ── Whitelist (user registration approval) ──────────────────────────────────

def add_to_whitelist(username, ip, device_info=None):
    """Add a newly-registered user to the whitelist with status 'pending'.
    If an entry already exists for this username, update the IP and reset to pending."""
    ip = normalize_ip(ip)
    existing = execute(
        "SELECT * FROM user_whitelist WHERE username = ?", (username,), fetchone=True
    )
    if existing:
        execute(
            "UPDATE user_whitelist SET ip = ?, device_info = ?, status = 'pending', updated_at = ? WHERE username = ?",
            (ip, device_info or "Unknown device", now_ph(), username),
            commit=True,
        )
    else:
        try:
            execute(
                "INSERT INTO user_whitelist (username, ip, device_info, status, created_at, updated_at) "
                "VALUES (?, ?, ?, 'pending', ?, ?)",
                (username, ip, device_info or "Unknown device", now_ph(), now_ph()),
                commit=True,
            )
        except DB_INTEGRITY_ERRORS:
            # Race condition: another worker inserted between our SELECT and INSERT — safe to ignore
            pass


def get_whitelist_entry_by_username(username):
    return execute(
        "SELECT * FROM user_whitelist WHERE username = ?", (username,), fetchone=True
    )


def list_whitelist(status=None):
    if status:
        return execute(
            "SELECT * FROM user_whitelist WHERE status = ? ORDER BY created_at DESC",
            (status,),
            fetchall=True,
        )
    return execute("SELECT * FROM user_whitelist ORDER BY created_at DESC", fetchall=True)


def update_whitelist_status(entry_id, status, reviewed_by=None, notes=None):
    execute(
        "UPDATE user_whitelist SET status = ?, reviewed_by = ?, admin_notes = ?, updated_at = ? WHERE id = ?",
        (status, reviewed_by or "admin", notes or "", now_ph(), entry_id),
        commit=True,
    )
    # Sync to users table
    entry = execute("SELECT username FROM user_whitelist WHERE id = ?", (entry_id,), fetchone=True)
    if entry:
        approved_val = True if status == "approved" else False
        execute(
            "UPDATE users SET approved = ? WHERE username = ?",
            (approved_val, entry["username"]),
            commit=True,
        )
