from functools import wraps
from flask import request, session, redirect, url_for, flash, g, abort
from models import (
    get_allowed_ip,
    get_blocked_ip,
    create_login_request,
    create_notification,
    record_log,
)


def normalize_ip(ip: str) -> str:
    """Normalize IP address for consistent comparison."""
    if not ip:
        return "127.0.0.1"
    ip = ip.strip().lower() if isinstance(ip, str) else str(ip).strip().lower()
    # Remove port if present (handle cases like "192.168.1.1:8080")
    if ':' in ip and not ip.startswith('['):  # IPv4 with port
        ip = ip.split(':')[0]
    elif ip.startswith('[') and ']:' in ip:  # IPv6 with port like [::1]:8080
        ip = ip.split(']:')[0].strip('[]')
    return ip


def get_client_ip():
    """Get the client IP address from the request, normalizing it for consistency."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
    else:
        ip = request.remote_addr or "127.0.0.1"
    return normalize_ip(ip)


def is_ip_blocked(ip: str) -> bool:
    """Check if the IP address is blocked."""
    ip = normalize_ip(ip)
    blocked = get_blocked_ip(ip)
    return bool(blocked and blocked["active"])


def is_ip_whitelisted(ip: str) -> bool:
    """Check if the IP address is whitelisted/approved."""
    ip = normalize_ip(ip)
    allowed = get_allowed_ip(ip)
    return bool(allowed and allowed["active"])


def require_admin(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Administrator access is required to view that page.", "danger")
            return redirect(url_for("dashboard"))
        return view_func(*args, **kwargs)

    return wrapper


def record_login_request_if_missing(username: str, ip: str, device_info: str = None):
    ip = normalize_ip(ip)
    create_login_request(username=username, ip=ip, device_info=device_info)
    create_notification(
        title="New access request pending approval",
        message=f"Login request from {ip} for {username} requires admin approval.",
        level="warning",
        target_role="admin",
    )
    record_log(
        user_id=None,
        username=username,
        ip=ip,
        event="New login request created for unknown IP",
        category="security",
        success=False,
    )


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        return view_func(*args, **kwargs)

    return wrapper
