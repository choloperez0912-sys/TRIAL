from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from security import get_client_ip, is_ip_blocked
from models import (
    create_user,
    get_user_by_username,
    record_log,
    count_recent_failed_attempts,
    block_ip,
    DB_INTEGRITY_ERRORS,
    add_to_whitelist,
    get_whitelist_entry_by_username,
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
            return redirect(url_for("auth.login") + "?tab=register")

        if password != confirm:
            flash("Passwords do not match.", "warning")
            return redirect(url_for("auth.login") + "?tab=register")

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "warning")
            return redirect(url_for("auth.login") + "?tab=register")

        ip_address = get_client_ip()
        password_hash = generate_password_hash(password)

        try:
            # Create user with approved=False (pending admin approval)
            create_user(username, password_hash, role="user", approved=False)
        except DB_INTEGRITY_ERRORS:
            flash("That username is already taken.", "danger")
            return redirect(url_for("auth.login") + "?tab=register")

        # Add to whitelist with status 'pending'
        add_to_whitelist(username, ip_address, device_info=request.user_agent.string)

        flash(
            "Registration successful! Your account is pending admin approval. "
            "You will be able to log in once an administrator approves your account.",
            "info",
        )
        return redirect(url_for("auth.login"))

    return redirect(url_for("auth.login") + "?tab=register")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip_address = get_client_ip()

        if is_ip_blocked(ip_address):
            flash("Your IP address has been blocked due to suspicious activity.", "danger")
            return redirect(url_for("auth.login"))

        user = get_user_by_username(username)

        if user and check_password_hash(user["password_hash"], password):
            # Admin always bypasses whitelist check
            if user["role"] == "admin":
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                record_log(user["id"], username, ip_address, "Successful authentication", "authentication", True)
                flash("Logged in successfully.", "success")
                return redirect(url_for("dashboard"))

            # For regular users: check whitelist approval status
            whitelist_entry = get_whitelist_entry_by_username(username)

            if not whitelist_entry:
                # No whitelist entry — not registered properly or removed
                flash("Your account is not in the approval queue. Please register first.", "warning")
                record_log(None, username, ip_address, "Login attempt — no whitelist entry", "authentication", False)
                return redirect(url_for("auth.login"))

            status = whitelist_entry["status"]

            if status == "pending":
                flash(
                    "Your account is pending admin approval. Please wait for an administrator to review your request.",
                    "warning",
                )
                record_log(user["id"], username, ip_address, "Login denied — account pending approval", "authentication", False)
                return redirect(url_for("auth.login"))

            if status == "rejected":
                flash(
                    "Your account registration has been rejected. Contact the administrator for more information.",
                    "danger",
                )
                record_log(user["id"], username, ip_address, "Login denied — account rejected", "authentication", False)
                return redirect(url_for("auth.login"))

            if status == "approved":
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"] if "role" in user.keys() else "user"
                record_log(user["id"], username, ip_address, "Successful authentication", "authentication", True)
                flash("Logged in successfully.", "success")
                return redirect(url_for("dashboard"))

            # Unknown status — deny
            flash("Your account status is unknown. Contact the administrator.", "danger")
            return redirect(url_for("auth.login"))

        # Bad credentials
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
