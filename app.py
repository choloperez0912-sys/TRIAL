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
    return camera_mode, camera_source


@app.after_request
def strip_server_headers(response):
    """Remove headers that reveal server technology to scanners."""
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)
    return response


@app.before_request
def enforce_network_policies():
    g.client_ip = get_client_ip()
    if is_ip_blocked(g.client_ip):
        return render_template("access_denied.html", ip=g.client_ip, reason="This IP is blocked."), 403


@app.route("/health")
@limiter.limit("30 per minute")
def health_check():
    return "OK", 200


@app.route("/")
@login_required
def dashboard():
    metrics = fetch_dashboard_metrics()
    recent_logs = list_recent_logs(limit=10)
    camera_mode, camera_source = resolve_camera_source()
    camera_stream.configure(camera_mode, camera_source)
    camera_online = camera_stream.start()
    unread_notifications = list_notifications(target_role=session.get("role", "user"), only_unread=True)
    return render_template(
        "dashboard.html",
        metrics=metrics,
        recent_logs=recent_logs,
        camera_online=camera_online,
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
        camera_stream.stop()
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
    """Generator that yields MJPEG frames with low-latency frame dropping."""
    import time

    TARGET_FPS = 25
    frame_interval = 1.0 / TARGET_FPS
    last_sent_time = 0.0
    empty_count = 0

    while True:
        frame_bytes, frame_time = camera_stream.get_frame()

        if frame_bytes:
            empty_count = 0
            now = time.time()
            if now - last_sent_time >= frame_interval:
                last_sent_time = now
                yield (
                    b"--frame\r\n"
                    b"Content-Type: image/jpeg\r\n\r\n" + frame_bytes + b"\r\n"
                )
            else:
                time.sleep(0.001)
        else:
            empty_count += 1
            if empty_count > 50:
                break
            time.sleep(0.02)


@app.route("/stream")
@login_required
def stream_feed():
    return Response(generate_frames(), mimetype="multipart/x-mixed-replace; boundary=frame")


@app.route("/logs")
@login_required
@require_admin
def logs():
    recent_logs = list_recent_logs(limit=100)
    return render_template(
        "logs.html",
        active_page="logs",
        logs=recent_logs,
    )


@app.route("/ip-management", methods=["GET", "POST"])
@login_required
@require_admin
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


@app.route("/admin/whitelist")
@login_required
@require_admin
def admin_whitelist():
    all_entries = list_whitelist()
    return render_template(
        "admin_whitelist.html",
        active_page="admin_whitelist",
        entries=all_entries,
    )


@app.route("/admin/whitelist/<int:entry_id>/<action>", methods=["POST"])
@login_required
@require_admin
def handle_whitelist_action(entry_id, action):
    if action not in ("approve", "reject"):
        flash("Invalid action.", "danger")
        return redirect(url_for("admin_whitelist"))

    admin_notes = f"{'Approved' if action == 'approve' else 'Rejected'} by {session.get('username')}"
    status = "approved" if action == "approve" else "rejected"
    update_whitelist_status(entry_id, status, reviewed_by=session.get("username"), notes=admin_notes)

    if action == "approve":
        create_notification(
            title="Account approved",
            message=f"User account has been approved by {session.get('username')}.",
            level="success",
        )
        flash("Account approved. The user can now log in.", "success")
    else:
        create_notification(
            title="Account rejected",
            message=f"User account has been rejected by {session.get('username')}.",
            level="danger",
        )
        flash("Account has been rejected.", "warning")

    return redirect(url_for("admin_whitelist"))


@app.route("/admin/requests")
@login_required
@require_admin
def admin_requests():
    return redirect(url_for("admin_whitelist"))


@app.route("/cam")
def public_cam():
    camera_mode, camera_source = resolve_camera_source()
    camera_stream.configure(camera_mode, camera_source)
    camera_stream.start()
    return render_template("public_camera.html", camera_url=camera_source)


@app.route("/cam/stream")
def public_stream_feed():
    return Response(generate_frames(), mimetype="multipart/x-mixed-replace; boundary=frame")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=False)
