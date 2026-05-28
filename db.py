import os
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SQLITE_DB_PATH = Path(os.environ.get("SQLITE_DB_PATH", BASE_DIR / "database.db"))

try:
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.errors import UniqueViolation
except ImportError:
    psycopg = None
    dict_row = None
    UniqueViolation = None

DB_INTEGRITY_ERRORS = (sqlite3.IntegrityError, UniqueViolation) if UniqueViolation else (sqlite3.IntegrityError,)


def is_postgres():
    """Check if PostgreSQL is configured by looking for non-empty DATABASE_URL"""
    db_url = os.environ.get("DATABASE_URL", "").strip()
    return bool(db_url)


def get_db_connection():
    if is_postgres():
        if psycopg is None:
            raise RuntimeError(
                "PostgreSQL support requires psycopg. Install it with psycopg[binary] or psycopg2-binary."
            )
        database_url = os.environ.get("DATABASE_URL", "").strip()
        return psycopg.connect(database_url, autocommit=False, row_factory=dict_row)

    conn = sqlite3.connect(SQLITE_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def adapt_query(query: str) -> str:
    return query.replace("?", "%s") if is_postgres() else query


def _sqlite_has_column(conn, table: str, column: str) -> bool:
    cursor = conn.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cursor.fetchall())


def execute(query: str, params=None, fetchone=False, fetchall=False, commit=False):
    params = params or ()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(adapt_query(query), params)
        result = None
        if fetchone:
            result = cursor.fetchone()
        elif fetchall:
            result = cursor.fetchall()
        if commit:
            conn.commit()
        return result
    finally:
        conn.close()


def init_db():
    if not is_postgres():
        SQLITE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = get_db_connection()
    try:
        if is_postgres():
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    approved BOOLEAN NOT NULL DEFAULT false,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS logs (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    username TEXT,
                    ip TEXT,
                    event TEXT NOT NULL,
                    category TEXT NOT NULL,
                    success BOOLEAN NOT NULL DEFAULT false,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS allowed_ips (
                    id SERIAL PRIMARY KEY,
                    ip TEXT UNIQUE NOT NULL,
                    label TEXT,
                    active BOOLEAN NOT NULL DEFAULT true,
                    approved_by TEXT,
                    approved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id SERIAL PRIMARY KEY,
                    ip TEXT UNIQUE NOT NULL,
                    reason TEXT,
                    active BOOLEAN NOT NULL DEFAULT true,
                    blocked_by TEXT,
                    blocked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS login_requests (
                    id SERIAL PRIMARY KEY,
                    username TEXT,
                    ip TEXT NOT NULL,
                    device_info TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    admin_notes TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS notifications (
                    id SERIAL PRIMARY KEY,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    level TEXT NOT NULL DEFAULT 'info',
                    target_role TEXT NOT NULL DEFAULT 'admin',
                    is_read BOOLEAN NOT NULL DEFAULT false,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS system_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS user_whitelist (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    ip TEXT NOT NULL,
                    device_info TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    reviewed_by TEXT,
                    admin_notes TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            conn.commit()
        else:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    approved INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            if not _sqlite_has_column(conn, "users", "role"):
                conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
            if not _sqlite_has_column(conn, "users", "approved"):
                conn.execute("ALTER TABLE users ADD COLUMN approved INTEGER NOT NULL DEFAULT 0")
            if not _sqlite_has_column(conn, "users", "created_at"):
                conn.execute("ALTER TABLE users ADD COLUMN created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    username TEXT,
                    ip TEXT,
                    event TEXT NOT NULL,
                    category TEXT NOT NULL,
                    success INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            if not _sqlite_has_column(conn, "logs", "created_at"):
                conn.execute("ALTER TABLE logs ADD COLUMN created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS allowed_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE NOT NULL,
                    label TEXT,
                    active INTEGER NOT NULL DEFAULT 1,
                    approved_by TEXT,
                    approved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            if not _sqlite_has_column(conn, "allowed_ips", "approved_at"):
                conn.execute("ALTER TABLE allowed_ips ADD COLUMN approved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP")
            if not _sqlite_has_column(conn, "allowed_ips", "created_at"):
                conn.execute("ALTER TABLE allowed_ips ADD COLUMN created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE NOT NULL,
                    reason TEXT,
                    active INTEGER NOT NULL DEFAULT 1,
                    blocked_by TEXT,
                    blocked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            if not _sqlite_has_column(conn, "blocked_ips", "blocked_at"):
                conn.execute("ALTER TABLE blocked_ips ADD COLUMN blocked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS login_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    ip TEXT NOT NULL,
                    device_info TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    admin_notes TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            if not _sqlite_has_column(conn, "login_requests", "created_at"):
                conn.execute("ALTER TABLE login_requests ADD COLUMN created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP")
            if not _sqlite_has_column(conn, "login_requests", "updated_at"):
                conn.execute("ALTER TABLE login_requests ADD COLUMN updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    level TEXT NOT NULL DEFAULT 'info',
                    target_role TEXT NOT NULL DEFAULT 'admin',
                    is_read INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            if not _sqlite_has_column(conn, "notifications", "created_at"):
                conn.execute("ALTER TABLE notifications ADD COLUMN created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS system_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS user_whitelist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    ip TEXT NOT NULL,
                    device_info TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    reviewed_by TEXT,
                    admin_notes TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.commit()
    finally:
        conn.close()


def get_user_camera_url(user_id):
    row = execute("SELECT camera_url FROM users WHERE id = ?", (user_id,), fetchone=True)
    return row["camera_url"] if row else None


def set_user_camera_url(user_id, camera_url):
    execute(
        "UPDATE users SET camera_url = ? WHERE id = ?",
        (camera_url, user_id),
        commit=True,
    )


def get_public_camera_url():
    public_user_id = os.environ.get("PUBLIC_USER_ID")
    if public_user_id:
        row = execute("SELECT camera_url FROM users WHERE id = ?", (public_user_id,), fetchone=True)
    else:
        row = execute("SELECT camera_url FROM users ORDER BY id LIMIT 1", fetchone=True)
    return row["camera_url"] if row else None
