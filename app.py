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
        # Naive datetimes from PostgreSQL are UTC — localize before converting
        value = value.replace(tzinfo=UTC)
    value = value.astimezone(PH_TZ)
    return value.strftime("%b %d, %Y %I:%M %p PHT")


app.config.from_object(Config)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# FIX: Talisman force_https must be False on Railway (Railway handles HTTPS at the proxy level)
# Forcing HTTPS inside the container causes redirect loops
Talisman(app, content_security_policy=None, force_https=False)

limiter = Limiter(key_func=get_remote_address, default_limits=[app.config["IP_RATE_LIMIT"]])
limiter.init_app(app)

app.register_blueprint(auth_bp)

init_db()
ensure_admin_user(app.config["ADMIN_USERNAME"], app.config["ADMIN_PASSWORD"])

# Whitelist localhost by default
create_allowed_ip("127.0.0.1", label="Localhost (default)", approved_by="system")
create_allowed_ip("localhost", label="Localhost domain (default)", approved_by="system")

camera_stream = CameraStream()


def resolve_camera_source():
    camera_mode = get_system_setting("camera.mode", app.config["CAMERA_MODE"])
    camera_source = get_system_setting(
        "camera.source",
        app.config["PUBLIC_CAMERA_URL"] if camera_mode == "public" else str(app.config["LOCAL_CAMERA_INDEX"]),
    )
    return camera_mode, camera_source


@app.before_request
def enforce_network_policies():
    g.client_ip = get_client_ip()
    endpoint = request.endpoint or ""

    if is_ip_blocked(g.client_ip):
        return render_template("access_denied.html", ip=g.client_ip, reason="This IP is blocked."), 403

    # FIX: added "health_check" to match the actual function name of the /health route
    safe_endpoints = {"static", "auth.login", "auth.register", "health_check"}

    # Allow logged-in admins to access admin and IP management pages
    admin_endpoints = {"admin_requests", "handle_request_action", "ip_management", "notifications"}
    if session.get("role") == "admin" and endpoint in admin_endpoints:
        return

    if endpoint in safe_endpoints:
        return

    if not is_ip_whitelisted(g.client_ip):
        return render_template(
            "access_denied.html",
            ip=g.client_ip,
            reason="Your IP address is not approved for system access.",
        ), 403


@app.route("/health")
def health_check():
    return "OK", 200


@app.route("/")
@login_required
def dashboard():
    metrics = fetch_dashboard_metrics()
    recent_logs = list_recent_logs(limit=10)
    unread_notifications = list_notifications(target_role=session.get("role", "user"), only_unread=True)
    return render_template(
        "dashboard.html",
        metrics=metrics,
        recent_logs=recent_logs,
        notifications=unread_notifications,
        active_page="dashboard",
    )


@app.route("/camera", methods=["GET", "POST"])
@login_required
def camera():
    camera_mode, camera_source = resolve_camera_source()

    if request.method == "POST":
        camera_mode = request.form.get("camera_mode", "local").lower()
        camera_source = request.form.get("camera_source", "").strip()
        if camera_mode != "public":
            camera_mode = "local"
            camera_source = request.form.get("camera_source", str(app.config["LOCAL_CAMERA_INDEX"]))

        set_system_setting("camera.mode", camera_mode)
        set_system_setting("camera.source", camera_source)
        camera_stream.configure(camera_mode, camera_source)
        flash("Camera configuration updated successfully.", "success")
        return redirect(url_for("camera"))

    camera_stream.configure(camera_mode, camera_source)
    stream_ok = camera_stream.start()

    return render_template(
        "cctv.html",
        active_page="camera",
        camera_mode=camera_mode,
        camera_source=camera_source,
        stream_ok=stream_ok,
        camera_status=camera_stream.get_status(),
    )


def generate_frames():
    while True:
        frame_bytes = camera_stream.get_frame()
        if frame_bytes:
            yield (
                b"--frame\r\n"
                b"Content-Type: image/jpeg\r\n\r\n" + frame_bytes + b"\r\n"
            )


@app.route("/stream")
@login_required
def stream_feed():
    return Response(generate_frames(), mimetype="multipart/x-mixed-replace; boundary=frame")


@app.route("/logs")
@login_required
def logs():
    recent_logs = list_recent_logs(limit=100)
    return render_template(
        "logs.html",
        active_page="logs",
        logs=recent_logs,
    )


@app.route("/ip-management", methods=["GET", "POST"])
@login_required
def ip_management():
    allowed_ips = list_allowed_ips()
    blocked_ips = list_blocked_ips()

    if request.method == "POST":
        action = request.form.get("action")
        ip_address = request.form.get("ip_address", "").strip()
        ip_address = normalize_ip(ip_address)
        reason = request.form.get("reason", "Manual security action")

        if action == "allow" and ip_address:
            create_allowed_ip(ip_address, label="Manual approval", approved_by=session.get("username"))
            create_notification(
                title="IP approved",
                message=f"{ip_address} was manually approved by {session.get('username')}",
                level="success",
            )
            flash(f"{ip_address} was added to the approved IP list.", "success")
        elif action == "block" and ip_address:
            from models import block_ip
            block_ip(ip_address, reason, blocked_by=session.get("username"))
            create_notification(
                title="IP blocked",
                message=f"{ip_address} was blocked by {session.get('username')}",
                level="danger",
            )
            flash(f"{ip_address} has been blocked.", "warning")
        elif action == "unblock" and ip_address:
            from models import unblock_ip
            unblock_ip(ip_address)
            flash(f"{ip_address} has been unblocked.", "success")

        return redirect(url_for("ip_management"))

    return render_template(
        "ip_management.html",
        active_page="ip_management",
        allowed_ips=allowed_ips,
        blocked_ips=blocked_ips,
    )


@app.route("/notifications", methods=["GET", "POST"])
@login_required
def notifications():
    if request.method == "POST":
        notification_id = request.form.get("notification_id")
        if notification_id:
            mark_notification_read(int(notification_id))
        return redirect(url_for("notifications"))

    notifications_list = list_notifications(target_role=session.get("role", "user"))
    return render_template(
        "notifications.html",
        active_page="notifications",
        notifications=notifications_list,
    )


@app.route("/admin/requests")
@login_required
@require_admin
def admin_requests():
    pending_requests = list_login_requests(status="pending")
    return render_template(
        "admin_requests.html",
        active_page="admin_requests",
        requests=pending_requests,
    )


@app.route("/admin/requests/<int:request_id>/<action>", methods=["POST"])
@login_required
@require_admin
def handle_request_action(request_id, action):
    request_record = next(
        (item for item in list_login_requests(status="pending") if item["id"] == request_id),
        None,
    )
    if not request_record:
        flash("Login request not found.", "danger")
        return redirect(url_for("admin_requests"))

    if action == "approve":
        create_allowed_ip(request_record["ip"], label="Admin approval", approved_by=session.get("username"))
        update_login_request(request_id, "approved", admin_notes=f"Approved by {session.get('username')}")
        create_notification(
            title="Login request approved",
            message=f"IP {request_record['ip']} has been approved for {request_record['username']}",
            level="success",
        )
        flash("Login request approved and IP whitelist updated.", "success")
    elif action == "deny":
        update_login_request(request_id, "denied", admin_notes=f"Denied by {session.get('username')}")
        create_notification(
            title="Login request denied",
            message=f"Access from {request_record['ip']} was denied.",
            level="danger",
        )
        flash("Login request has been denied.", "warning")
    else:
        flash("Invalid admin action.", "danger")

    return redirect(url_for("admin_requests"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=False)
