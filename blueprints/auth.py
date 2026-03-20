"""
Blueprint auth — authentification, setup, langue.
Routes : /setup /login /logout /forgot-password /reset-password /set_lang
"""
import time as _time
from urllib.parse import urlparse

from flask import (Blueprint, redirect, render_template,
                   request, session, url_for)
from flask_login import current_user, login_required, login_user, logout_user

import config
import database as db
import notifications
import snmp_collector as collector
from models import User
from scheduler_utils import scheduler, _start_job

auth_bp = Blueprint("auth", __name__)

# ── Rate limiting login (anti brute-force) ────────────────────────────────────
_login_attempts: dict[str, list[float]] = {}
_LOGIN_MAX     = 5
_LOGIN_WINDOW  = 300
_LOGIN_LOCKOUT = 30


def _check_login_rate(ip: str) -> tuple[bool, int]:
    now = _time.time()
    attempts = _login_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < _LOGIN_WINDOW]
    _login_attempts[ip] = attempts
    if len(attempts) < _LOGIN_MAX:
        return True, 0
    oldest = attempts[0]
    wait = _LOGIN_LOCKOUT * (len(attempts) - _LOGIN_MAX + 1)
    remaining = int(wait - (now - oldest))
    return remaining <= 0, max(0, remaining)


def _record_login_fail(ip: str):
    now = _time.time()
    lst = _login_attempts.setdefault(ip, [])
    lst.append(now)
    _login_attempts[ip] = lst[-50:]


def _clear_login_rate(ip: str):
    _login_attempts.pop(ip, None)


# ── Routes ────────────────────────────────────────────────────────────────────

@auth_bp.route("/set_lang/<lang>")
def set_lang(lang: str):
    if lang in ("fr", "en"):
        session["lang"] = lang
    ref = request.referrer
    if ref:
        ref_host = urlparse(ref).netloc
        own_host = urlparse(request.host_url).netloc
        if not ref_host or ref_host == own_host:
            return redirect(ref)
    return redirect(url_for("main.overview"))


@auth_bp.route("/setup", methods=["GET", "POST"])
def setup():
    if not db.needs_setup():
        return redirect(url_for("main.overview"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm",  "")
        r_name    = request.form.get("r_name",   "").strip()
        r_ip      = request.form.get("r_ip",     "").strip()
        r_ver     = int(request.form.get("r_version", 2))
        r_comm    = request.form.get("r_community", "public").strip()
        r_port    = int(request.form.get("r_port", 161))
        r_poll    = int(request.form.get("r_poll", 60))
        r_ret     = int(request.form.get("r_retention", 30))
        r_v3_user = request.form.get("r_v3_username", "").strip()
        r_v3_ap   = request.form.get("r_v3_auth_protocol", "SHA")
        r_v3_ak   = request.form.get("r_v3_auth_password", "")
        r_v3_pp   = request.form.get("r_v3_priv_protocol", "AES")
        r_v3_pk   = request.form.get("r_v3_priv_password", "")
        r_v3_lvl  = request.form.get("r_v3_security_level", "authPriv")

        if not username or not password:
            error = "Le nom d'utilisateur et le mot de passe sont requis."
        elif password != confirm:
            error = "Les mots de passe ne correspondent pas."
        elif len(password) < 8:
            error = "Le mot de passe doit contenir au moins 8 caractères."
        elif not r_name or not r_ip:
            error = "Le nom et l'IP du routeur sont requis."
        elif r_ver == 3 and not r_v3_user:
            error = "Le nom d'utilisateur SNMPv3 est requis."
        else:
            db.create_user(username, password, is_admin=True)
            router = db.create_router(
                r_name, r_ip,
                snmp_version=r_ver,
                community=r_comm, port=r_port,
                poll_interval=r_poll, retention_days=r_ret,
                snmp_v3_username=r_v3_user or None,
                snmp_v3_auth_protocol=r_v3_ap,
                snmp_v3_auth_password=r_v3_ak or None,
                snmp_v3_priv_protocol=r_v3_pp,
                snmp_v3_priv_password=r_v3_pk or None,
                snmp_v3_security_level=r_v3_lvl,
            )
            _start_job(router)
            scheduler.add_job(collector.poll, args=[router], id="first_poll",
                              replace_existing=True)
            return redirect(url_for("auth.login"))

    return render_template("setup.html", error=error)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.overview"))

    error     = None
    wait_secs = 0

    if request.method == "POST":
        ip = request.remote_addr or "0.0.0.0"
        allowed, wait_secs = _check_login_rate(ip)

        if not allowed:
            error = f"Trop de tentatives. Réessayez dans {wait_secs}s."
        else:
            username  = request.form.get("username", "").strip()
            password  = request.form.get("password", "")
            user_data = db.verify_password(username, password)

            if user_data:
                _clear_login_rate(ip)
                login_user(User(user_data), remember=False)
                db.add_audit(username, "login",
                             f"Connexion depuis {ip}", ip=ip)
                next_url = request.args.get("next", "")
                parsed   = urlparse(next_url)
                if parsed.scheme or parsed.netloc:
                    next_url = ""
                return redirect(next_url or url_for("main.overview"))

            _record_login_fail(ip)
            error = "Identifiants incorrects."
            db.add_audit(username or "?", "login_failed",
                         f"Échec de connexion depuis {ip}", ip=ip)

    try:
        reset_enabled = db.get_settings().get("password_reset_enabled", "0") == "1"
    except Exception:
        reset_enabled = False
    return render_template("login.html", error=error, wait_secs=wait_secs,
                           password_reset_enabled=reset_enabled)


@auth_bp.route("/logout")
@login_required
def logout():
    db.add_audit(current_user.username, "logout", "", ip=request.remote_addr)
    logout_user()
    return redirect(url_for("auth.login"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("main.overview"))
    try:
        cfg = db.get_settings()
    except Exception:
        cfg = {}
    if cfg.get("password_reset_enabled", "0") != "1":
        return redirect(url_for("auth.login"))

    sent = False
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if email:
            user = db.get_user_by_email(email)
            if user and cfg.get("smtp_host"):
                raw_token = db.create_reset_token(user["id"])
                reset_url = url_for("auth.reset_password", token=raw_token, _external=True)
                notifications.send_email(
                    cfg["smtp_host"],
                    int(cfg.get("smtp_port", 587)),
                    cfg.get("smtp_user", ""),
                    cfg.get("smtp_pass", ""),
                    cfg.get("smtp_from", ""),
                    [user["email"]],
                    "info",
                    "Réinitialisation de mot de passe — HuwaControl",
                    f"Cliquez sur ce lien pour réinitialiser votre mot de passe "
                    f"(valable 30 min) :\n\n{reset_url}",
                )
                db.add_audit(user["username"], "password_reset_request",
                             f"Demande depuis {request.remote_addr}",
                             ip=request.remote_addr)
        sent = True
    return render_template("forgot_password.html", sent=sent)


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token: str):
    if current_user.is_authenticated:
        return redirect(url_for("main.overview"))
    try:
        cfg = db.get_settings()
    except Exception:
        cfg = {}
    if cfg.get("password_reset_enabled", "0") != "1":
        return redirect(url_for("auth.login"))

    user_id = db.validate_reset_token(token)
    if not user_id:
        return render_template("reset_password.html", invalid=True)

    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")
        if len(password) < 8:
            error = "Le mot de passe doit contenir au moins 8 caractères."
        elif password != confirm:
            error = "Les mots de passe ne correspondent pas."
        else:
            uid = db.consume_reset_token(token)
            if uid:
                db.update_password(uid, password)
                user_data = db.get_user_by_id(uid)
                db.add_audit(
                    user_data["username"] if user_data else "?",
                    "password_reset_done",
                    f"Mot de passe réinitialisé depuis {request.remote_addr}",
                    ip=request.remote_addr,
                )
                return render_template("reset_password.html", success=True)
            return render_template("reset_password.html", invalid=True)

    return render_template("reset_password.html", token=token, error=error)
