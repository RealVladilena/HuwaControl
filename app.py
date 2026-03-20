import csv
import hashlib
import io
import json
import logging
import secrets
import time
import urllib.request as _urllib_req
from datetime import datetime
from urllib.parse import urlparse

from flask import (Flask, Response, jsonify, redirect, render_template,
                   request, session, url_for, flash)
from flask_login import (LoginManager, UserMixin, current_user,
                         login_required, login_user, logout_user)
from werkzeug.middleware.proxy_fix import ProxyFix
from apscheduler.schedulers.background import BackgroundScheduler

import config
import database as db
import snmp_collector as collector
import notifications
import ping_collector
import reports
import syslog_receiver as syslog_recv
import snmp_trap_receiver as trap_recv
import i18n as _i18n

logging.basicConfig(
    level=logging.DEBUG if config.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("app")

# ─── Flask & Login ────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ── Session / cookie security ─────────────────────────────────────────────────
app.config.update(
    SESSION_COOKIE_HTTPONLY  = True,
    SESSION_COOKIE_SAMESITE  = "Lax",
    SESSION_COOKIE_SECURE    = False,   # passer à True derrière HTTPS
    PERMANENT_SESSION_LIFETIME = 86400 * 7,  # 7 jours
    REMEMBER_COOKIE_HTTPONLY = True,
    REMEMBER_COOKIE_SAMESITE = "Lax",
    REMEMBER_COOKIE_DURATION = 86400 * 7,
)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Veuillez vous connecter."


# ─── i18n ─────────────────────────────────────────────────────────────────────

_SUPPORTED_LANGS = ("fr", "en")


def _get_locale() -> str:
    lang = session.get("lang")
    if lang in _SUPPORTED_LANGS:
        return lang
    best = request.accept_languages.best_match(_SUPPORTED_LANGS)
    return best or "fr"


# ── Security headers (toutes les réponses) ────────────────────────────────────
@app.after_request
def add_security_headers(resp):
    resp.headers["X-Frame-Options"]           = "DENY"
    resp.headers["X-Content-Type-Options"]    = "nosniff"
    resp.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    resp.headers["X-XSS-Protection"]          = "1; mode=block"
    resp.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
    # CSP permissif pour Chart.js CDN + FontAwesome CDN
    resp.headers["Content-Security-Policy"]   = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return resp


# ── Rate limiting login (anti brute-force) ───────────────────────────────────
import time as _time
_login_attempts: dict[str, list[float]] = {}  # ip → [timestamps]
_LOGIN_MAX     = 5    # tentatives max
_LOGIN_WINDOW  = 300  # fenêtre 5 minutes
_LOGIN_LOCKOUT = 30   # lockout par tentative supplémentaire (sec)

def _check_login_rate(ip: str) -> tuple[bool, int]:
    """Retourne (autorisé, secondes_avant_retry)."""
    now = _time.time()
    attempts = _login_attempts.get(ip, [])
    # Purger les tentatives hors fenêtre
    attempts = [t for t in attempts if now - t < _LOGIN_WINDOW]
    _login_attempts[ip] = attempts
    if len(attempts) < _LOGIN_MAX:
        return True, 0
    # Lockout exponentiel basé sur le nombre de dépassements
    oldest = attempts[0]
    wait = _LOGIN_LOCKOUT * (len(attempts) - _LOGIN_MAX + 1)
    remaining = int(wait - (now - oldest))
    return remaining <= 0, max(0, remaining)

def _record_login_fail(ip: str):
    now = _time.time()
    lst = _login_attempts.setdefault(ip, [])
    lst.append(now)
    # Ne garder que les 50 dernières entrées max
    _login_attempts[ip] = lst[-50:]

def _clear_login_rate(ip: str):
    _login_attempts.pop(ip, None)


# ─── Vérification des mises à jour GitHub ─────────────────────────────────────

_update_available: bool = False


def check_github_version() -> None:
    global _update_available
    try:
        cfg = db.get_settings()
    except Exception:
        return
    if cfg.get("update_check_enabled", "1") == "0":
        _update_available = False
        return
    try:
        req = _urllib_req.Request(
            "https://api.github.com/repos/RealVladilena/HuwaControl/releases/latest",
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": "HuwaControl"},
        )
        with _urllib_req.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        latest  = data.get("tag_name", "").lstrip("v")
        current = config.APP_VERSION.lstrip("v")
        _update_available = bool(latest) and latest != current
        db.set_setting("_latest_github_version", latest)
        log.info("GitHub update check: latest=%s current=%s available=%s",
                 latest, current, _update_available)
    except Exception as e:
        log.warning("GitHub update check failed: %s", e)


class User(UserMixin):
    def __init__(self, data: dict):
        self.id       = str(data["id"])
        self.username = data["username"]
        self.is_admin = data["is_admin"]


@login_manager.user_loader
def load_user(user_id: str):
    data = db.get_user_by_id(int(user_id))
    return User(data) if data else None


# ─── Scheduler ────────────────────────────────────────────────────────────────

scheduler = BackgroundScheduler(daemon=True)
scheduler.start()


def _start_job(router: dict) -> None:
    job_id = f"snmp_{router['id']}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    if router.get("enabled"):
        scheduler.add_job(
            collector.poll, "interval",
            args=[router],
            seconds=router["poll_interval"],
            id=job_id,
        )
        log.info("Job démarré : %s toutes les %ds", router["name"], router["poll_interval"])


def _stop_job(router_id: int) -> None:
    job_id = f"snmp_{router_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
        log.info("Job arrêté : router_id=%d", router_id)


# ─── Language switcher ────────────────────────────────────────────────────────

@app.route("/set_lang/<lang>")
def set_lang(lang: str):
    if lang in _SUPPORTED_LANGS:
        session["lang"] = lang
    ref = request.referrer
    if ref:
        ref_host = urlparse(ref).netloc
        own_host = urlparse(request.host_url).netloc
        if not ref_host or ref_host == own_host:
            return redirect(ref)
    return redirect(url_for("overview"))


# ─── Hooks ────────────────────────────────────────────────────────────────────

@app.before_request
def guard():
    """Redirige vers /setup si aucun utilisateur n'existe encore."""
    if request.endpoint in ("setup", "static", "login", "logout", "set_lang",
                            "forgot_password", "reset_password"):
        return None
    if db.needs_setup():
        return redirect(url_for("setup"))


# ─── Context processor ────────────────────────────────────────────────────────

@app.context_processor
def inject_routers():
    try:
        routers = db.get_all_routers() if not db.needs_setup() else []
    except Exception:
        routers = []
    lang = _get_locale()
    def _(text: str) -> str:
        return _i18n.translate(text, lang)
    return {
        "all_routers":      routers,
        "APP_VERSION":      config.APP_VERSION,
        "APP_BUILD_DATE":   config.APP_BUILD_DATE,
        "_":                _,
        "current_lang":     lang,
        "update_available": _update_available,
    }


# ─── Utilitaires ──────────────────────────────────────────────────────────────

def fmt_uptime(ticks):
    if ticks is None:
        return "N/A"
    s = int(ticks) // 100
    d, r = divmod(s, 86400)
    h, r = divmod(r, 3600)
    m = r // 60
    if d >= 1:
        return f"{d}j {h:02d}h"     # ex : "57j 09h"
    if h >= 1:
        return f"{h:02d}h {m:02d}m" # ex : "09h 28m"
    return f"{m}m"


def fmt_pps(pps):
    if pps is None:
        return "N/A"
    if pps >= 1e6:
        return f"{pps/1e6:.1f}M pps"
    if pps >= 1e3:
        return f"{pps/1e3:.1f}K pps"
    return f"{int(pps)} pps"


def fmt_bps(bps):
    if bps is None:
        return "N/A"
    if bps >= 1e9:
        return f"{bps/1e9:.2f} Gbps"
    if bps >= 1e6:
        return f"{bps/1e6:.2f} Mbps"
    if bps >= 1e3:
        return f"{bps/1e3:.1f} Kbps"
    return f"{int(bps)} bps"


def _active_router_id() -> int | None:
    """Retourne le router_id depuis les args, le cookie ou le premier dispo."""
    rid = request.args.get("router_id", type=int) \
       or session.get("router_id")
    if rid:
        session["router_id"] = rid
        return rid
    routers = db.get_all_routers()
    if routers:
        session["router_id"] = routers[0]["id"]
        return routers[0]["id"]
    return None


# ─── Auth ─────────────────────────────────────────────────────────────────────

@app.route("/setup", methods=["GET", "POST"])
def setup():
    if not db.needs_setup():
        return redirect(url_for("overview"))

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
            # Premier poll immédiat en arrière-plan
            scheduler.add_job(collector.poll, args=[router], id="first_poll",
                              replace_existing=True)
            log.info("Setup terminé — admin: %s, routeur: %s (%s)", username, r_name, r_ip)
            return redirect(url_for("login"))

    return render_template("setup.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("overview"))

    error      = None
    wait_secs  = 0

    if request.method == "POST":
        ip       = request.remote_addr or "0.0.0.0"
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
                # Valider le paramètre next pour éviter un open redirect
                from urllib.parse import urlparse
                next_url = request.args.get("next", "")
                parsed   = urlparse(next_url)
                if parsed.scheme or parsed.netloc:
                    next_url = ""   # URL absolue = refusée
                return redirect(next_url or url_for("overview"))

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


@app.route("/logout")
@login_required
def logout():
    db.add_audit(current_user.username, "logout", "", ip=request.remote_addr)
    logout_user()
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("overview"))
    try:
        cfg = db.get_settings()
    except Exception:
        cfg = {}
    if cfg.get("password_reset_enabled", "0") != "1":
        return redirect(url_for("login"))

    sent = False
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if email:
            user = db.get_user_by_email(email)
            if user and cfg.get("smtp_host"):
                raw_token = db.create_reset_token(user["id"])
                reset_url = url_for("reset_password", token=raw_token, _external=True)
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
        # Toujours afficher "email envoyé" pour ne pas révéler si le compte existe
        sent = True
    return render_template("forgot_password.html", sent=sent)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token: str):
    if current_user.is_authenticated:
        return redirect(url_for("overview"))
    try:
        cfg = db.get_settings()
    except Exception:
        cfg = {}
    if cfg.get("password_reset_enabled", "0") != "1":
        return redirect(url_for("login"))

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


# ─── Pages principales ────────────────────────────────────────────────────────

@app.route("/")
@login_required
def overview():
    rid = _active_router_id()
    router = db.get_router(rid) if rid else None
    return render_template("overview.html", router=router,
                           active_page="overview")


@app.route("/vpn")
@login_required
def vpn_page():
    rid    = _active_router_id()
    router = db.get_router(rid) if rid else None
    return render_template("vpn.html", router=router, active_page="vpn")


@app.route("/interfaces")
@login_required
def interfaces():
    rid = _active_router_id()
    ifaces = db.get_known_interfaces(rid) if rid else []
    return render_template("interfaces.html", ifaces=ifaces,
                           active_page="interfaces")


@app.route("/performance")
@login_required
def performance():
    return render_template("performance.html", active_page="performance")


@app.route("/history")
@login_required
def history():
    return render_template("history.html", active_page="history")


@app.route("/routers")
@login_required
def routers_page():
    return render_template("routers.html", active_page="routers")


@app.route("/clients")
@login_required
def clients_page():
    return render_template("clients.html", active_page="clients")


@app.route("/wifi")
@login_required
def wifi_page():
    return render_template("wifi.html", active_page="wifi")


@app.route("/events")
@login_required
def events_page():
    return render_template("events.html", active_page="events")


@app.route("/ping")
@login_required
def ping_page():
    return render_template("ping.html", active_page="ping")


@app.route("/routing-table")
@login_required
def routing_table_page():
    return render_template("routing_table.html", active_page="routing")


@app.route("/notifications")
@login_required
def notifications_page():
    if not current_user.is_admin:
        return redirect(url_for("overview"))
    try:
        webhooks = db.get_discord_webhooks()
    except Exception:
        webhooks = []
    try:
        tg_bots = db.get_telegram_bots()
    except Exception:
        tg_bots = []
    try:
        cfg = db.get_settings()
    except Exception:
        cfg = {}
    return render_template("notifications_page.html", active_page="notifications",
                           webhooks=webhooks, tg_bots=tg_bots, cfg=cfg)


@app.route("/audit")
@login_required
def audit_page():
    if not current_user.is_admin:
        return redirect(url_for("overview"))
    return render_template("audit.html", active_page="audit")


@app.route("/settings")
@login_required
def settings():
    users = db.get_all_users() if current_user.is_admin else []
    try:
        webhooks = db.get_discord_webhooks()
    except Exception as e:
        log.error("get_discord_webhooks: %s", e)
        webhooks = []
    try:
        tg_bots = db.get_telegram_bots()
    except Exception as e:
        log.error("get_telegram_bots: %s", e)
        tg_bots = []
    try:
        ping_targets = db.get_ping_targets()
    except Exception as e:
        log.error("get_ping_targets: %s", e)
        ping_targets = []
    try:
        cfg = db.get_settings()
    except Exception as e:
        log.error("get_settings: %s", e)
        cfg = {}
    return render_template("settings.html", active_page="settings",
                           users=users, webhooks=webhooks,
                           tg_bots=tg_bots, ping_targets=ping_targets, cfg=cfg)


# ─── API — routeurs ───────────────────────────────────────────────────────────

@app.route("/api/routers", methods=["GET"])
@login_required
def api_routers_list():
    return jsonify(db.get_all_routers())


@app.route("/api/routers", methods=["POST"])
@login_required
def api_routers_create():
    d = request.json or {}
    missing = [f for f in ("name", "ip") if not d.get(f)]
    if missing:
        return jsonify({"error": f"Champs requis : {', '.join(missing)}"}), 400
    router = db.create_router(
        name=d["name"].strip(), ip=d["ip"].strip(),
        snmp_version=int(d.get("snmp_version", 2)),
        community=d.get("snmp_community", "public"),
        port=int(d.get("snmp_port", 161)),
        poll_interval=int(d.get("poll_interval", 60)),
        retention_days=int(d.get("retention_days", 30)),
        snmp_v3_username=d.get("snmp_v3_username"),
        snmp_v3_auth_protocol=d.get("snmp_v3_auth_protocol", "SHA"),
        snmp_v3_auth_password=d.get("snmp_v3_auth_password"),
        snmp_v3_priv_protocol=d.get("snmp_v3_priv_protocol", "AES"),
        snmp_v3_priv_password=d.get("snmp_v3_priv_password"),
        snmp_v3_security_level=d.get("snmp_v3_security_level", "authPriv"),
    )
    _start_job(router)
    scheduler.add_job(collector.poll, args=[router],
                      id=f"firstpoll_{router['id']}", replace_existing=True)
    return jsonify(router), 201


@app.route("/api/routers/<int:rid>", methods=["GET"])
@login_required
def api_routers_get(rid):
    r = db.get_router(rid)
    return jsonify(r) if r else ("", 404)


@app.route("/api/routers/<int:rid>", methods=["PUT"])
@login_required
def api_routers_update(rid):
    d = request.json or {}
    router = db.update_router(rid, **d)
    if not router:
        return ("", 404)
    _start_job(router)   # reconfigure le job (intervalle peut avoir changé)
    return jsonify(router)


@app.route("/api/routers/<int:rid>", methods=["DELETE"])
@login_required
def api_routers_delete(rid):
    _stop_job(rid)
    db.delete_router(rid)
    if session.get("router_id") == rid:
        session.pop("router_id", None)
    return ("", 204)


@app.route("/api/routers/<int:rid>/poll", methods=["POST"])
@login_required
def api_routers_poll(rid):
    router = db.get_router(rid)
    if not router:
        return ("", 404)
    try:
        collector.poll(router)
        return jsonify({"ok": True, "ts": int(time.time())})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ─── API — données ────────────────────────────────────────────────────────────

def _rid():
    """Récupère router_id depuis les args ou la session."""
    rid = request.args.get("router_id", type=int) or session.get("router_id")
    if not rid:
        routers = db.get_all_routers()
        rid = routers[0]["id"] if routers else None
    return rid


@app.route("/api/status")
@login_required
def api_status():
    rid = _rid()
    if not rid:
        return jsonify({}), 200
    sys_data = db.get_latest_system(rid)
    ifaces   = db.get_interfaces_latest(rid)
    router   = db.get_router(rid)
    return jsonify({
        "router_id":   rid,
        "router_name": router["name"] if router else "",
        "router_ip":   router["ip"]   if router else "",
        "timestamp":   sys_data.get("ts"),
        "sys_name":    sys_data.get("sys_name"),
        "uptime_fmt":  fmt_uptime(sys_data.get("sys_uptime")),
        "location":    sys_data.get("location"),
        "cpu_usage":   sys_data.get("cpu_usage"),
        "mem_usage":   sys_data.get("mem_usage"),
        "temperature": sys_data.get("temperature"),
        "interfaces": {
            "total": len(ifaces),
            "up":    sum(1 for i in ifaces if i.get("if_status") == 1),
            "down":  sum(1 for i in ifaces if i.get("if_status") != 1),
        },
    })


@app.route("/api/interfaces")
@login_required
def api_interfaces():
    rid = _rid()
    if not rid:
        return jsonify([])
    ifaces  = db.get_interfaces_latest(rid)
    aliases = db.get_interface_aliases(rid)
    result  = []
    for iface in ifaces:
        bps_rows   = db.get_bps_history(rid, iface["if_index"], hours=1)
        latest_bps = bps_rows[-1] if bps_rows else {}
        alias      = aliases.get(iface["if_index"])
        result.append({
            **iface,
            "alias":       alias,
            "display_name": f"{alias} ({iface['if_name']})" if alias else iface["if_name"],
            "in_bps_fmt":  fmt_bps(latest_bps.get("in_bps")),
            "out_bps_fmt": fmt_bps(latest_bps.get("out_bps")),
            "in_pps_fmt":  fmt_pps(latest_bps.get("in_pps")),
            "out_pps_fmt": fmt_pps(latest_bps.get("out_pps")),
            "in_pps":      latest_bps.get("in_pps"),
            "out_pps":     latest_bps.get("out_pps"),
        })
    return jsonify(result)


@app.route("/api/interfaces/<int:if_index>/bps")
@login_required
def api_interface_bps(if_index):
    rid   = _rid()
    hours = request.args.get("hours", 24, type=int)
    rows  = db.get_bps_history(rid, if_index, hours=hours) if rid else []
    return jsonify({
        "labels":  [datetime.fromtimestamp(r["ts"]).strftime("%H:%M") for r in rows],
        "in_bps":  [r["in_bps"]  for r in rows],
        "out_bps": [r["out_bps"] for r in rows],
        "in_pps":  [r.get("in_pps")  for r in rows],
        "out_pps": [r.get("out_pps") for r in rows],
    })


@app.route("/api/performance")
@login_required
def api_performance():
    rid   = _rid()
    hours = request.args.get("hours", 24, type=int)
    rows  = db.get_system_history(rid, hours=hours) if rid else []
    return jsonify({
        "labels": [datetime.fromtimestamp(r["ts"]).strftime("%H:%M") for r in rows],
        "cpu":    [r["cpu_usage"]   for r in rows],
        "mem":    [r["mem_usage"]   for r in rows],
        "temp":   [r["temperature"] for r in rows],
    })


@app.route("/api/history")
@login_required
def api_history():
    rid  = _rid()
    days = request.args.get("days", 30, type=int)
    rows = db.get_system_history_days(rid, days=days) if rid else []
    return jsonify({
        "labels":  [r["hour"]    for r in rows],
        "cpu_avg": [r["cpu_avg"] for r in rows],
        "cpu_max": [r["cpu_max"] for r in rows],
        "mem_avg": [r["mem_avg"] for r in rows],
        "mem_max": [r["mem_max"] for r in rows],
        "temp_avg":[r["temp_avg"]for r in rows],
    })


@app.route("/api/clients")
@login_required
def api_clients():
    rid    = _rid()
    router = db.get_router(rid) if rid else None
    if not router:
        return jsonify([])
    try:
        clients = collector.collect_clients(router)
        return jsonify(clients)
    except Exception as e:
        log.error("collect_clients: %s", e)
        return jsonify([])


@app.route("/api/wifi")
@login_required
def api_wifi():
    rid    = _rid()
    router = db.get_router(rid) if rid else None
    if not router:
        return jsonify({"interfaces": [], "clients": []})
    try:
        # Interfaces WiFi depuis le dernier poll
        all_ifaces = db.get_interfaces_latest(rid)
        raw_wifi = [
            i for i in all_ifaces
            if any(k in (i.get("if_name") or "").lower()
                   for k in ("wlan", "radio", "dot11", "wifi", "bss"))
        ]
        wifi_ifaces = []
        for iface in raw_wifi:
            bps_rows   = db.get_bps_history(rid, iface["if_index"], hours=1)
            latest_bps = bps_rows[-1] if bps_rows else {}
            wifi_ifaces.append({
                **iface,
                "in_bps":      latest_bps.get("in_bps"),
                "out_bps":     latest_bps.get("out_bps"),
                "in_bps_fmt":  fmt_bps(latest_bps.get("in_bps")),
                "out_bps_fmt": fmt_bps(latest_bps.get("out_bps")),
            })
        # Clients WiFi via Huawei WLAN MIB
        try:
            wifi_clients = collector.collect_wifi_clients(router)
        except Exception:
            wifi_clients = []
        return jsonify({"interfaces": wifi_ifaces, "clients": wifi_clients})
    except Exception as e:
        log.error("api_wifi: %s", e)
        return jsonify({"interfaces": [], "clients": []})


@app.route("/api/events")
@login_required
def api_events():
    rid   = request.args.get("router_id", type=int) or None
    limit = request.args.get("limit", 200, type=int)
    rows  = db.get_events(router_id=rid, limit=limit)
    return jsonify(rows)


@app.route("/api/events/daily")
@login_required
def api_events_daily():
    rid  = request.args.get("router_id", type=int) or _rid() or None
    days = request.args.get("days", 60, type=int)
    rows = db.get_events_daily(router_id=rid, days=days)
    return jsonify(rows)


@app.route("/api/vpn")
@login_required
def api_vpn():
    """Retourne les tunnels VPN (interfaces Tunnel/GRE + IKE SA si disponible)."""
    rid    = _rid()
    router = db.get_router(rid) if rid else None
    if not router:
        return jsonify({"tunnels": [], "ike_sas": []})
    ifaces = db.get_interfaces_latest(rid)
    vpn_kw = ("tunnel", "gre", "ipsec", "l2tp", "pppoe", "vpn")
    tunnels = [
        i for i in ifaces
        if any(k in (i.get("if_name") or "").lower() for k in vpn_kw)
    ]
    ike_sas = []
    try:
        ike_sas = collector.collect_ike_sas(router)
    except Exception:
        pass
    return jsonify({"tunnels": tunnels, "ike_sas": ike_sas})


# ─── API — Discord webhooks ───────────────────────────────────────────────────

@app.route("/api/discord", methods=["GET"])
@login_required
def api_discord_list():
    return jsonify(db.get_discord_webhooks())


@app.route("/api/discord", methods=["POST"])
@login_required
def api_discord_create():
    if not current_user.is_admin:
        return ("", 403)
    d = request.json or {}
    if not d.get("url"):
        return jsonify({"error": "URL requise"}), 400
    wh = db.create_discord_webhook(
        name=d.get("name", "Webhook"),
        url=d["url"],
        on_info=d.get("on_info", True),
        on_warning=d.get("on_warning", True),
        on_error=d.get("on_error", True),
    )
    return jsonify(wh), 201


@app.route("/api/discord/<int:wh_id>", methods=["PUT"])
@login_required
def api_discord_update(wh_id):
    if not current_user.is_admin:
        return ("", 403)
    d  = request.json or {}
    wh = db.update_discord_webhook(wh_id, **d)
    return jsonify(wh) if wh else ("", 404)


@app.route("/api/discord/<int:wh_id>", methods=["DELETE"])
@login_required
def api_discord_delete(wh_id):
    if not current_user.is_admin:
        return ("", 403)
    db.delete_discord_webhook(wh_id)
    return ("", 204)


@app.route("/api/discord/<int:wh_id>/test", methods=["POST"])
@login_required
def api_discord_test(wh_id):
    webhooks = db.get_discord_webhooks()
    wh = next((w for w in webhooks if w["id"] == wh_id), None)
    if not wh:
        return ("", 404)
    ok, err = notifications.send_discord_test(wh["url"], wh["name"])
    return jsonify({"ok": ok, "error": err})


# ─── API — paramètres ─────────────────────────────────────────────────────────

@app.route("/api/settings", methods=["GET"])
@login_required
def api_settings_get():
    return jsonify(db.get_settings())


@app.route("/api/settings", methods=["POST"])
@login_required
def api_settings_post():
    if not current_user.is_admin:
        return ("", 403)
    d = request.json or {}
    for k, v in d.items():
        db.set_setting(k, str(v))
    return jsonify({"ok": True})


@app.route("/api/events/<int:event_id>/ack", methods=["POST"])
@login_required
def api_event_ack(event_id):
    ok = db.ack_event(event_id, current_user.username)
    if ok:
        db.add_audit(current_user.username, "event_ack",
                     f"Acquittement événement #{event_id}", ip=request.remote_addr)
    return jsonify({"ok": ok})


# ─── API — audit log ──────────────────────────────────────────────────────────

@app.route("/api/audit")
@login_required
def api_audit():
    if not current_user.is_admin:
        return ("", 403)
    limit = request.args.get("limit", 200, type=int)
    rows  = db.get_audit(limit=limit)
    return jsonify(rows)


# ─── API — Telegram bots ──────────────────────────────────────────────────────

@app.route("/api/telegram", methods=["GET"])
@login_required
def api_telegram_list():
    return jsonify(db.get_telegram_bots())


@app.route("/api/telegram", methods=["POST"])
@login_required
def api_telegram_create():
    if not current_user.is_admin:
        return ("", 403)
    d = request.json or {}
    if not d.get("bot_token") or not d.get("chat_id"):
        return jsonify({"error": "bot_token et chat_id requis"}), 400
    bot = db.create_telegram_bot(
        name=d.get("name", "Telegram"),
        bot_token=d["bot_token"],
        chat_id=str(d["chat_id"]),
        on_info=d.get("on_info", True),
        on_warning=d.get("on_warning", True),
        on_error=d.get("on_error", True),
    )
    db.add_audit(current_user.username, "telegram_create",
                 f"Ajout bot Telegram {bot['name']}", ip=request.remote_addr)
    return jsonify(bot), 201


@app.route("/api/telegram/<int:bot_id>", methods=["PUT"])
@login_required
def api_telegram_update(bot_id):
    if not current_user.is_admin:
        return ("", 403)
    d   = request.json or {}
    bot = db.update_telegram_bot(bot_id, **d)
    return jsonify(bot) if bot else ("", 404)


@app.route("/api/telegram/<int:bot_id>", methods=["DELETE"])
@login_required
def api_telegram_delete(bot_id):
    if not current_user.is_admin:
        return ("", 403)
    db.delete_telegram_bot(bot_id)
    db.add_audit(current_user.username, "telegram_delete",
                 f"Suppression bot Telegram #{bot_id}", ip=request.remote_addr)
    return ("", 204)


@app.route("/api/telegram/<int:bot_id>/test", methods=["POST"])
@login_required
def api_telegram_test(bot_id):
    bots = db.get_telegram_bots()
    bot  = next((b for b in bots if b["id"] == bot_id), None)
    if not bot:
        return ("", 404)
    ok, err = notifications.send_telegram_test(
        bot["bot_token"], bot["chat_id"], bot["name"]
    )
    return jsonify({"ok": ok, "error": err})


# ─── API — email test ─────────────────────────────────────────────────────────

@app.route("/api/email/test", methods=["POST"])
@login_required
def api_email_test():
    if not current_user.is_admin:
        return ("", 403)
    cfg = db.get_settings()
    to_raw   = cfg.get("smtp_to", "")
    to_addrs = [a.strip() for a in to_raw.split(",") if a.strip()]
    if not cfg.get("smtp_host") or not to_addrs:
        return jsonify({"ok": False, "error": "SMTP non configuré ou destinataires manquants"})
    ok, err = notifications.send_email_test(
        cfg["smtp_host"],
        int(cfg.get("smtp_port", 587)),
        cfg.get("smtp_user", ""),
        cfg.get("smtp_pass", ""),
        cfg.get("smtp_from", ""),
        to_addrs,
    )
    return jsonify({"ok": ok, "error": err})


# ─── API — cibles ping ────────────────────────────────────────────────────────

@app.route("/api/ping-targets", methods=["GET"])
@login_required
def api_ping_targets_list():
    rid = request.args.get("router_id", type=int) or None
    return jsonify(db.get_ping_targets(router_id=rid))


@app.route("/api/ping-targets", methods=["POST"])
@login_required
def api_ping_targets_create():
    if not current_user.is_admin:
        return ("", 403)
    d = request.json or {}
    if not d.get("host") or not d.get("label"):
        return jsonify({"error": "host et label requis"}), 400
    target = db.create_ping_target(
        label=d["label"].strip(),
        host=d["host"].strip(),
        router_id=d.get("router_id"),
    )
    return jsonify(target), 201


@app.route("/api/ping-targets/<int:tid>", methods=["PUT"])
@login_required
def api_ping_targets_update(tid):
    if not current_user.is_admin:
        return ("", 403)
    d      = request.json or {}
    target = db.update_ping_target(tid, **d)
    return jsonify(target) if target else ("", 404)


@app.route("/api/ping-targets/<int:tid>", methods=["DELETE"])
@login_required
def api_ping_targets_delete(tid):
    if not current_user.is_admin:
        return ("", 403)
    db.delete_ping_target(tid)
    return ("", 204)


@app.route("/api/ping/<int:tid>/history")
@login_required
def api_ping_history(tid):
    hours = request.args.get("hours", 24, type=int)
    rows  = db.get_ping_history(tid, hours=hours)
    return jsonify({
        "labels":  [datetime.fromtimestamp(r["ts"]).strftime("%H:%M") for r in rows],
        "rtt":     [r["rtt_ms"] for r in rows],
        "success": [r["success"] for r in rows],
    })


@app.route("/api/ping/<int:tid>/sla")
@login_required
def api_ping_sla(tid):
    hours = request.args.get("hours", 24, type=int)
    return jsonify(db.get_sla_stats(tid, hours=hours))


# ─── API — table de routage (live SNMP) ──────────────────────────────────────

@app.route("/api/routing-table")
@login_required
def api_routing_table():
    rid    = _rid()
    router = db.get_router(rid) if rid else None
    if not router:
        return jsonify([])
    try:
        routes = collector.collect_routing_table(router)
        return jsonify(routes)
    except Exception as e:
        log.error("collect_routing_table: %s", e)
        return jsonify([])


# ─── API — seuils par interface ───────────────────────────────────────────────

@app.route("/api/thresholds")
@login_required
def api_thresholds_list():
    rid = _rid()
    if not rid:
        return jsonify([])
    return jsonify(db.get_interface_thresholds(rid))


@app.route("/api/thresholds", methods=["POST"])
@login_required
def api_thresholds_set():
    if not current_user.is_admin:
        return ("", 403)
    d = request.json or {}
    rid      = d.get("router_id") or _rid()
    if_index = d.get("if_index")
    if not rid or if_index is None:
        return jsonify({"error": "router_id et if_index requis"}), 400
    row = db.set_interface_threshold(
        rid, int(if_index),
        d.get("if_name", ""),
        int(d.get("bw_warn_pct", 80))
    )
    return jsonify(row)


@app.route("/api/thresholds/<int:if_index>", methods=["DELETE"])
@login_required
def api_thresholds_delete(if_index):
    if not current_user.is_admin:
        return ("", 403)
    rid = _rid()
    if rid:
        db.delete_interface_threshold(rid, if_index)
    return ("", 204)


# ─── API — alias d'interfaces ─────────────────────────────────────────────────

@app.route("/api/aliases")
@login_required
def api_aliases_list():
    rid = _rid()
    if not rid:
        return jsonify({})
    return jsonify(db.get_interface_aliases(rid))


@app.route("/api/aliases", methods=["POST"])
@login_required
def api_aliases_set():
    d        = request.json or {}
    rid      = d.get("router_id") or _rid()
    if_index = d.get("if_index")
    alias    = (d.get("alias") or "").strip()
    if not rid or if_index is None:
        return jsonify({"error": "router_id et if_index requis"}), 400
    if alias:
        db.set_interface_alias(rid, int(if_index), alias)
    else:
        db.delete_interface_alias(rid, int(if_index))
    return jsonify({"ok": True})


# ─── API — rapport journalier forcé ──────────────────────────────────────────

@app.route("/api/reports/send", methods=["POST"])
@login_required
def api_reports_send():
    if not current_user.is_admin:
        return ("", 403)
    db.add_audit(current_user.username, "report_manual",
                 "Envoi manuel du rapport", ip=request.remote_addr)
    try:
        reports.send_daily_report()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ─── API — exports CSV ────────────────────────────────────────────────────────

@app.route("/api/export/events")
@login_required
def api_export_events():
    rid   = request.args.get("router_id", type=int) or None
    rows  = db.get_events(router_id=rid, limit=10000)
    buf   = io.StringIO()
    w     = csv.writer(buf)
    w.writerow(["id", "ts", "datetime", "level", "category", "router", "title", "message", "acked"])
    for r in rows:
        w.writerow([
            r["id"],
            r["ts"],
            datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M:%S"),
            r["level"], r["category"],
            r.get("router_name", ""),
            r["title"], r.get("message", ""),
            r.get("acked", False),
        ])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=events.csv"})


@app.route("/api/export/interfaces")
@login_required
def api_export_interfaces():
    rid   = _rid()
    ifaces = db.get_interfaces_latest(rid) if rid else []
    buf   = io.StringIO()
    w     = csv.writer(buf)
    w.writerow(["if_index", "if_name", "if_status", "speed_mbps",
                "in_octets", "out_octets", "in_errors", "out_errors",
                "in_ucast_pkts", "out_ucast_pkts"])
    for r in ifaces:
        w.writerow([r["if_index"], r["if_name"], r["if_status"], r["speed_mbps"],
                    r["in_octets"], r["out_octets"], r["in_errors"], r["out_errors"],
                    r["in_ucast_pkts"], r["out_ucast_pkts"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=interfaces.csv"})


@app.route("/api/export/performance")
@login_required
def api_export_performance():
    rid   = _rid()
    hours = request.args.get("hours", 24, type=int)
    rows  = db.get_system_history(rid, hours=hours) if rid else []
    buf   = io.StringIO()
    w     = csv.writer(buf)
    w.writerow(["ts", "datetime", "cpu_usage", "mem_usage", "temperature"])
    for r in rows:
        w.writerow([
            r["ts"],
            datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M:%S"),
            r["cpu_usage"], r["mem_usage"], r["temperature"],
        ])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=performance.csv"})


@app.route("/api/history/iface/<int:if_index>")
@login_required
def api_history_iface(if_index):
    rid  = _rid()
    days = request.args.get("days", 30, type=int)
    rows = db.get_bps_history_days(rid, if_index, days=days) if rid else []
    return jsonify({
        "labels":  [r["hour"]    for r in rows],
        "in_avg":  [r["in_avg"]  for r in rows],
        "in_max":  [r["in_max"]  for r in rows],
        "out_avg": [r["out_avg"] for r in rows],
        "out_max": [r["out_max"] for r in rows],
    })


# ─── API — utilisateurs ───────────────────────────────────────────────────────

@app.route("/api/users/password", methods=["POST"])
@login_required
def api_change_password():
    d = request.json or {}
    old, new, confirm = d.get("old"), d.get("new"), d.get("confirm")
    if not old or not new or not confirm:
        return jsonify({"error": "Champs incomplets"}), 400
    if new != confirm:
        return jsonify({"error": "Les mots de passe ne correspondent pas"}), 400
    if len(new) < 8:
        return jsonify({"error": "Minimum 8 caractères"}), 400
    user = db.verify_password(current_user.username, old)
    if not user:
        return jsonify({"error": "Mot de passe actuel incorrect"}), 403
    db.update_password(int(current_user.id), new)
    return jsonify({"ok": True})


@app.route("/api/users", methods=["POST"])
@login_required
def api_create_user():
    if not current_user.is_admin:
        return ("", 403)
    d = request.json or {}
    if not d.get("username") or not d.get("password"):
        return jsonify({"error": "username et password requis"}), 400
    if len(d["password"]) < 8:
        return jsonify({"error": "Minimum 8 caractères"}), 400
    try:
        user = db.create_user(d["username"], d["password"],
                              is_admin=d.get("is_admin", False))
        return jsonify({"id": user["id"], "username": user["username"]}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/users/<int:uid>", methods=["DELETE"])
@login_required
def api_delete_user(uid):
    if not current_user.is_admin:
        return ("", 403)
    if uid == int(current_user.id):
        return jsonify({"error": "Impossible de supprimer son propre compte"}), 400
    db.delete_user(uid)
    return ("", 204)


# ─── Syslogs ──────────────────────────────────────────────────────────────────

@app.route("/logs")
@login_required
def logs_page():
    return render_template("logs.html", active_page="logs",
                           syslog_port=config.SYSLOG_HOST_PORT)


@app.route("/api/syslogs")
@login_required
def api_syslogs():
    limit       = request.args.get("limit", 200, type=int)
    offset      = request.args.get("offset", 0, type=int)
    severity    = request.args.get("severity", 7, type=int)
    search      = request.args.get("q", "")
    rows  = db.get_syslogs(limit=limit, severity_max=severity,
                           search=search, offset=offset)
    total = db.count_syslogs(severity_max=severity, search=search)
    return jsonify({"rows": rows, "total": total})


@app.route("/api/syslogs/stats")
@login_required
def api_syslogs_stats():
    hours = request.args.get("hours", 24, type=int)
    try:
        return jsonify(db.get_syslog_daily_stats(hours=hours))
    except Exception as e:
        log.error("api_syslogs_stats: %s", e)
        return jsonify({"error": str(e)}), 500




@app.route("/api/syslogs", methods=["DELETE"])
@login_required
def api_syslogs_purge():
    if not current_user.is_admin:
        return ("", 403)
    days = request.args.get("days", 30, type=int)
    db.purge_syslogs(days=days)
    return jsonify({"ok": True})


@app.route("/api/export/syslogs")
@login_required
def api_export_syslogs():
    rows = db.get_syslogs(limit=50000, severity_max=7)
    buf  = io.StringIO()
    buf.write("\ufeff")   # BOM pour Excel
    w = csv.writer(buf)
    w.writerow(["ts", "datetime", "source_ip", "severity", "facility", "hostname", "program", "message"])
    for r in rows:
        w.writerow([
            r["ts"],
            datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M:%S") if r["ts"] else "",
            r.get("source_ip", ""), r.get("severity", ""), r.get("facility", ""),
            r.get("hostname", ""), r.get("program", ""), r.get("message", ""),
        ])
    return Response(buf.getvalue(), mimetype="text/csv;charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=syslogs.csv"})


# ─── Acquittement en masse ────────────────────────────────────────────────────

@app.route("/api/events/ack-all", methods=["POST"])
@login_required
def api_events_ack_all():
    rid = (request.json or {}).get("router_id") or _rid() or None
    n   = db.ack_all_events(router_id=rid, username=current_user.username)
    db.add_audit(current_user.username, "ack_all_events",
                 f"router_id={rid} — {n} événements acquittés")
    return jsonify({"ok": True, "count": n})


# ─── ARP historique ───────────────────────────────────────────────────────────

@app.route("/api/arp")
@login_required
def api_arp():
    rid   = _rid()
    limit = request.args.get("limit", 500, type=int)
    rows  = db.get_arp_history(rid, limit=limit) if rid else []
    return jsonify(rows)


@app.route("/api/export/arp")
@login_required
def api_export_arp():
    rid  = _rid()
    rows = db.get_arp_history(rid, limit=50000) if rid else []
    buf  = io.StringIO()
    buf.write("\ufeff")
    w = csv.writer(buf)
    w.writerow(["mac", "ip", "first_seen", "last_seen", "first_seen_dt", "last_seen_dt"])
    for r in rows:
        w.writerow([
            r["mac"], r["ip"], r["first_seen"], r["last_seen"],
            datetime.fromtimestamp(r["first_seen"]).strftime("%Y-%m-%d %H:%M:%S"),
            datetime.fromtimestamp(r["last_seen"]).strftime("%Y-%m-%d %H:%M:%S"),
        ])
    return Response(buf.getvalue(), mimetype="text/csv;charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=arp_history.csv"})


# ─── DHCP leases ──────────────────────────────────────────────────────────────

@app.route("/api/dhcp")
@login_required
def api_dhcp():
    rid    = _rid()
    router = db.get_router(rid) if rid else None
    if not router:
        return jsonify([])
    try:
        leases = collector.collect_dhcp_leases(router)
        return jsonify(leases)
    except Exception as e:
        log.error("api_dhcp: %s", e)
        return jsonify([])


# ─── BGP / OSPF ───────────────────────────────────────────────────────────────

@app.route("/bgp-ospf")
@login_required
def bgp_ospf_page():
    rid    = _rid()
    router = db.get_router(rid) if rid else None
    return render_template("bgp_ospf.html", active_page="bgp_ospf", router=router)


@app.route("/api/bgp")
@login_required
def api_bgp():
    rid    = _rid()
    router = db.get_router(rid) if rid else None
    if not router:
        return jsonify([])
    try:
        return jsonify(collector.collect_bgp_neighbors(router))
    except Exception as e:
        log.error("api_bgp: %s", e)
        return jsonify([])


@app.route("/api/ospf")
@login_required
def api_ospf():
    rid    = _rid()
    router = db.get_router(rid) if rid else None
    if not router:
        return jsonify([])
    try:
        return jsonify(collector.collect_ospf_neighbors(router))
    except Exception as e:
        log.error("api_ospf: %s", e)
        return jsonify([])


# ─── Rapport consultable ──────────────────────────────────────────────────────

@app.route("/report")
@login_required
def report_page():
    return render_template("report.html", active_page="report")


@app.route("/api/reports/latest")
@login_required
def api_reports_latest():
    try:
        report = reports.build_report()
        return jsonify(report)
    except Exception as e:
        log.error("api_reports_latest: %s", e)
        return jsonify({"error": str(e)}), 500


# ─── Backup / Restore ─────────────────────────────────────────────────────────

@app.route("/api/backup")
@login_required
def api_backup():
    if not current_user.is_admin:
        return ("", 403)
    routers  = db.get_all_routers()
    settings = db.get_settings()
    aliases  = {}
    for r in routers:
        aliases[r["id"]] = db.get_interface_aliases(r["id"])
    ping_targets = db.get_ping_targets()
    # Masquer les secrets sensibles
    safe_routers = []
    for r in routers:
        sr = dict(r)
        if sr.get("snmp_v3_auth_pass"):
            sr["snmp_v3_auth_pass"] = "MASKED"
        if sr.get("snmp_v3_priv_pass"):
            sr["snmp_v3_priv_pass"] = "MASKED"
        safe_routers.append(sr)
    backup = {
        "version":      config.APP_VERSION,
        "exported_at":  int(time.time()),
        "routers":      safe_routers,
        "settings":     settings,
        "aliases":      aliases,
        "ping_targets": ping_targets,
    }
    return Response(
        __import__("json").dumps(backup, indent=2, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=huwacontrol_backup.json"}
    )


@app.route("/api/restore", methods=["POST"])
@login_required
def api_restore():
    if not current_user.is_admin:
        return ("", 403)
    try:
        data = request.json or {}
        restored = {"settings": 0, "ping_targets": 0}
        # Restaurer settings
        for k, v in (data.get("settings") or {}).items():
            db.set_setting(k, v)
            restored["settings"] += 1
        # Restaurer cibles ping (additif, pas de doublons sur host)
        existing_hosts = {t["host"] for t in db.get_ping_targets()}
        for t in (data.get("ping_targets") or []):
            if t.get("host") and t["host"] not in existing_hosts:
                db.add_ping_target(t["label"], t["host"])
                restored["ping_targets"] += 1
        db.add_audit(current_user.username, "restore_backup",
                     f"settings={restored['settings']} ping_targets={restored['ping_targets']}")
        return jsonify({"ok": True, "restored": restored})
    except Exception as e:
        log.error("api_restore: %s", e)
        return jsonify({"error": str(e)}), 500


# ─── Multi-routeur comparaison ────────────────────────────────────────────────

@app.route("/compare")
@login_required
def compare_page():
    routers = db.get_all_routers() if not db.needs_setup() else []
    return render_template("compare.html", active_page="compare", routers=routers)


# ─── Permissions utilisateurs ─────────────────────────────────────────────────

@app.route("/api/users/<int:uid>/perms", methods=["GET"])
@login_required
def api_user_perms_get(uid):
    if not current_user.is_admin:
        return ("", 403)
    return jsonify(db.get_user_router_perms(uid))


@app.route("/api/users/<int:uid>/perms", methods=["POST"])
@login_required
def api_user_perms_set(uid):
    if not current_user.is_admin:
        return ("", 403)
    d = request.json or {}
    router_id = d.get("router_id")
    can_write = bool(d.get("can_write", False))
    if not router_id:
        return jsonify({"error": "router_id requis"}), 400
    db.set_user_router_perm(uid, router_id, can_write)
    return jsonify({"ok": True})


@app.route("/api/users/<int:uid>/perms/<int:rid>", methods=["DELETE"])
@login_required
def api_user_perms_delete(uid, rid):
    if not current_user.is_admin:
        return ("", 403)
    db.delete_user_router_perm(uid, rid)
    return ("", 204)


@app.route("/api/users/<int:uid>/email", methods=["PUT"])
@login_required
def api_user_email(uid):
    if not current_user.is_admin:
        return ("", 403)
    email = (request.json or {}).get("email", "").strip()
    db.set_user_email(uid, email or None)
    return jsonify({"ok": True})


# ─── Démarrage ────────────────────────────────────────────────────────────────

db.init_pool()
db.init_db()

if not db.needs_setup():
    for _router in db.get_enabled_routers():
        _start_job(_router)
    # Job ping toutes les 60 secondes
    scheduler.add_job(
        ping_collector.poll_all_targets, "interval",
        seconds=60, id="ping_poll", replace_existing=True,
    )
    # Rapport quotidien (heure configurable via settings, défaut 7h)
    _cfg = db.get_settings()
    _report_hour = int(_cfg.get("report_hour", 7))
    scheduler.add_job(
        reports.send_daily_report, "cron",
        hour=_report_hour, minute=0, id="daily_report", replace_existing=True,
    )
    log.info("Jobs ping + rapport quotidien démarrés")

# Vérification des mises à jour GitHub (toutes les 6h + au démarrage)
scheduler.add_job(
    check_github_version, "interval",
    hours=6, id="github_update_check", replace_existing=True,
)
scheduler.add_job(
    check_github_version, id="github_update_check_init", replace_existing=True,
)

# Syslog receiver (UDP)
_syslog_receiver = syslog_recv.SyslogReceiver(port=config.SYSLOG_PORT)
_syslog_receiver.start()

# SNMP Trap receiver (UDP)
_trap_receiver = trap_recv.SnmpTrapReceiver(port=config.SNMP_TRAP_PORT)
_trap_receiver.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=config.DEBUG, use_reloader=False)
