from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from security import get_client_ip, is_ip_blocked, is_ip_whitelisted, record_login_request_if_missing
from models import (
    create_user,
    get_user_by_username,
    record_log,
    count_recent_failed_attempts,
    block_ip,
    create_allowed_ip,
    DB_INTEGRITY_ERRORS,
)

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not username or not password or not confirm:
            flash("Please fill in all fields.", "warning")
            return redirect(url_for("auth.register"))

        if password != confirm:
            flash("Passwords do not match.", "warning")
            return redirect(url_for("auth.register"))

        password_hash = generate_password_hash(password)
        try:
            create_user(username, password_hash, role="user", approved=True)
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("auth.login"))
        except DB_INTEGRITY_ERRORS:
            flash("That username is already taken.", "danger")
            return redirect(url_for("auth.register"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip_address = get_client_ip()

        if is_ip_blocked(ip_address):
            flash("Your IP address has been blocked.", "danger")
            return redirect(url_for("auth.login"))

        user = get_user_by_username(username)

        if user and check_password_hash(user["password_hash"], password):
            is_admin = user["role"] == "admin"

            if not is_ip_whitelisted(ip_address):
                if is_admin:
                    # Auto-whitelist the admin's IP on first successful login
                    # This is necessary so the admin can access Railway from any IP
                    create_allowed_ip(ip_address, label="Auto-approved admin IP", approved_by="system")
                else:
                    record_login_request_if_missing(username, ip_address, device_info=request.user_agent.string)
                    flash(
                        "This IP address is not approved yet. An admin request has been created.",
                        "warning",
                    )
                    return redirect(url_for("auth.login"))

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"] if "role" in user.keys() else "user"
            record_log(user["id"], username, ip_address, "Successful authentication", "authentication", True)
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))

        record_log(
            user["id"] if user else None,
            username,
            ip_address,
            "Failed authentication",
            "authentication",
            False,
        )

        failure_count = count_recent_failed_attempts(ip_address, window_minutes=15)
        if failure_count >= 5:
            block_ip(ip_address, "Brute force protection", blocked_by="system")
            flash(
                "Too many failed attempts. Your IP address has been blocked for security reasons.",
                "danger",
            )
        else:
            flash("Invalid username or password.", "danger")

        return redirect(url_for("auth.login"))

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
