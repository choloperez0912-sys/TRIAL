import os
from datetime import datetime
from dotenv import load_dotenv
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    Response,
    g,
    abort,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

from auth import auth_bp
from camera import CameraStream
from config import Config
from db import init_db
from models import (
    fetch_dashboard_metrics,
    list_recent_logs,
    list_notifications,
    list_allowed_ips,
    list_blocked_ips,
    list_login_requests,
    update_login_request,
    create_allowed_ip,
    create_notification,
    mark_notification_read,
    set_system_setting,
    get_system_setting,
    ensure_admin_user,
    list_whitelist,
    update_whitelist_status,
)
from security import get_client_ip, is_ip_blocked, is_ip_whitelisted, login_required, require_admin, normalize_ip

app = Flask(__name__, static_folder="static", template_folder="templates")


@app.template_filter("ph_time")
def ph_time_filter(value):
    """Format a datetime as Philippine Time (UTC+8)."""
    if not value:
        return ""
    from datetime import timezone, timedelta
    PH_TZ = timezone(timedelta(hours=8))
    UTC = timezone.utc
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    value = value.astimezone(PH_TZ)
    return value.strftime("%b %d, %Y %I:%M %p PHT")


app.config.from_object(Config)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

csp = {
    "default-src": "'self'",
    "img-src": "'self' data: blob:",
    "script-src": ["'self'", "cdn.jsdelivr.net", "'unsafe-inline'"],
    "style-src": ["'self'", "cdn.jsdelivr.net", "'unsafe-inline'"],
    "font-src": ["'self'", "cdn.jsdelivr.net"],
    "connect-src": "'self'",
}
Talisman(app, content_security_policy=csp, force_https=False)

limiter = Limiter(key_func=get_remote_address, default_limits=[app.config["IP_RATE_LIMIT"]])
limiter.init_app(app)

app.register_blueprint(auth_bp)

init_db()
ensure_admin_user(app.config["ADMIN_USERNAME"], app.config["ADMIN_PASSWORD"])

from db import DB_INTEGRITY_ERRORS
for _ip, _label in [("127.0.0.1", "Localhost (default)"), ("localhost", "Localhost domain (default)")]:
    try:
        create_allowed_ip(_ip, label=_label, approved_by="system")
    except DB_INTEGRITY_ERRORS:
        pass
    except Exception:
        pass

camera_stream = CameraStream()


def resolve_camera_source():
    camera_mode = get_system_setting("camera.mode", app.config["CAMERA_MODE"])
    camera_source = get_system_setting(
        "camera.source",
        app.config["PUBLIC_CAMERA_URL"] if camera_mode == "public" else str(app.config["LOCAL_CAMERA_INDEX"]),
    )
