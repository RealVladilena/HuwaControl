import json
import logging
import urllib.request as _urllib_req
from urllib.parse import urlparse

from flask import Flask, redirect, request, session, url_for
from flask_login import LoginManager
from werkzeug.middleware.proxy_fix import ProxyFix

import config
import database as db
import notifications
import ping_collector
import reports
import syslog_receiver as syslog_recv
import snmp_trap_receiver as trap_recv
import i18n as _i18n
from models import User
from scheduler_utils import scheduler, _start_job
from socket_manager import socketio

logging.basicConfig(
    level=logging.DEBUG if config.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("app")

# ─── Flask ────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

app.config.update(
    SESSION_COOKIE_HTTPONLY    = True,
    SESSION_COOKIE_SAMESITE    = "Lax",
    SESSION_COOKIE_SECURE      = False,   # passer à True derrière HTTPS
    PERMANENT_SESSION_LIFETIME = 86400 * 7,
    REMEMBER_COOKIE_HTTPONLY   = True,
    REMEMBER_COOKIE_SAMESITE   = "Lax",
    REMEMBER_COOKIE_DURATION   = 86400 * 7,
)

# ─── Flask-Login ──────────────────────────────────────────────────────────────

login_manager = LoginManager(app)
login_manager.login_view    = "auth.login"
login_manager.login_message = "Veuillez vous connecter."


@login_manager.user_loader
def load_user(user_id: str):
    data = db.get_user_by_id(int(user_id))
    return User(data) if data else None


# ─── Blueprints ───────────────────────────────────────────────────────────────

from blueprints.auth import auth_bp
from blueprints.main import main_bp
from blueprints.api  import api_bp
from metrics         import metrics_bp

app.register_blueprint(auth_bp)
app.register_blueprint(main_bp)
app.register_blueprint(api_bp)
app.register_blueprint(metrics_bp)

socketio.init_app(app, async_mode="threading", cors_allowed_origins="*")

# ─── Security headers ─────────────────────────────────────────────────────────

@app.after_request
def add_security_headers(resp):
    resp.headers["X-Frame-Options"]        = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    resp.headers["X-XSS-Protection"]       = "1; mode=block"
    resp.headers["Permissions-Policy"]     = "geolocation=(), microphone=(), camera=()"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return resp


# ─── Hooks ────────────────────────────────────────────────────────────────────

_BYPASS_ENDPOINTS = frozenset({
    "auth.setup", "auth.login", "auth.logout",
    "auth.set_lang", "auth.forgot_password", "auth.reset_password",
    "static",
})


@app.before_request
def guard():
    """Redirige vers /setup si aucun utilisateur n'existe encore."""
    if request.endpoint in _BYPASS_ENDPOINTS:
        return None
    if db.needs_setup():
        return redirect(url_for("auth.setup"))


# ─── Context processor ────────────────────────────────────────────────────────

_SUPPORTED_LANGS    = ("fr", "en")
_update_available: bool = False


def _get_locale() -> str:
    lang = session.get("lang")
    if lang in _SUPPORTED_LANGS:
        return lang
    best = request.accept_languages.best_match(_SUPPORTED_LANGS)
    return best or "fr"


@app.context_processor
def inject_globals():
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


# ─── Vérification des mises à jour GitHub ─────────────────────────────────────

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


# ─── Démarrage ────────────────────────────────────────────────────────────────

db.init_pool()
db.init_db()

scheduler.start()

if not db.needs_setup():
    for _router in db.get_enabled_routers():
        _start_job(_router)
    scheduler.add_job(
        ping_collector.poll_all_targets, "interval",
        seconds=60, id="ping_poll", replace_existing=True,
    )
    _cfg = db.get_settings()
    _report_hour = int(_cfg.get("report_hour", 7))
    scheduler.add_job(
        reports.send_daily_report, "cron",
        hour=_report_hour, minute=0, id="daily_report", replace_existing=True,
    )
    _weekly_hour = int(_cfg.get("weekly_report_hour", 8))
    scheduler.add_job(
        reports.send_weekly_report, "cron",
        day_of_week="mon", hour=_weekly_hour, minute=0,
        id="weekly_report", replace_existing=True,
    )
    log.info("Jobs ping + rapports quotidien/hebdo démarrés")

scheduler.add_job(
    check_github_version, "interval",
    hours=6, id="github_update_check", replace_existing=True,
)
scheduler.add_job(
    check_github_version, id="github_update_check_init", replace_existing=True,
)

_syslog_receiver = syslog_recv.SyslogReceiver(port=config.SYSLOG_PORT)
_syslog_receiver.start()

_trap_receiver = trap_recv.SnmpTrapReceiver(port=config.SNMP_TRAP_PORT)
_trap_receiver.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=config.DEBUG, use_reloader=False)
