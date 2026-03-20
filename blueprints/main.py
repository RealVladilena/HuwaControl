"""
Blueprint main — pages HTML principale.
Routes : /, /vpn, /interfaces, /performance, /history, /routers,
         /clients, /wifi, /events, /ping, /routing-table,
         /notifications, /audit, /settings, /logs,
         /bgp-ospf, /report, /compare, /dashboard
"""
from flask import Blueprint, redirect, render_template, url_for
from flask_login import current_user, login_required

import config
import database as db
from utils import _active_router_id, _rid

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
@login_required
def overview():
    rid    = _active_router_id()
    router = db.get_router(rid) if rid else None
    return render_template("overview.html", router=router, active_page="overview")


@main_bp.route("/vpn")
@login_required
def vpn_page():
    rid    = _active_router_id()
    router = db.get_router(rid) if rid else None
    return render_template("vpn.html", router=router, active_page="vpn")


@main_bp.route("/interfaces")
@login_required
def interfaces():
    rid    = _active_router_id()
    ifaces = db.get_known_interfaces(rid) if rid else []
    return render_template("interfaces.html", ifaces=ifaces, active_page="interfaces")


@main_bp.route("/performance")
@login_required
def performance():
    return render_template("performance.html", active_page="performance")


@main_bp.route("/history")
@login_required
def history():
    return render_template("history.html", active_page="history")


@main_bp.route("/routers")
@login_required
def routers_page():
    return render_template("routers.html", active_page="routers")


@main_bp.route("/clients")
@login_required
def clients_page():
    return render_template("clients.html", active_page="clients")


@main_bp.route("/wifi")
@login_required
def wifi_page():
    return render_template("wifi.html", active_page="wifi")


@main_bp.route("/events")
@login_required
def events_page():
    return render_template("events.html", active_page="events")


@main_bp.route("/ping")
@login_required
def ping_page():
    return render_template("ping.html", active_page="ping")


@main_bp.route("/routing-table")
@login_required
def routing_table_page():
    return render_template("routing_table.html", active_page="routing")


@main_bp.route("/notifications")
@login_required
def notifications_page():
    if not current_user.is_admin:
        return redirect(url_for("main.overview"))
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


@main_bp.route("/audit")
@login_required
def audit_page():
    if not current_user.is_admin:
        return redirect(url_for("main.overview"))
    return render_template("audit.html", active_page="audit")


@main_bp.route("/settings")
@login_required
def settings():
    import logging
    log = logging.getLogger("main")
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


@main_bp.route("/logs")
@login_required
def logs_page():
    return render_template("logs.html", active_page="logs",
                           syslog_port=config.SYSLOG_HOST_PORT)


@main_bp.route("/bgp-ospf")
@login_required
def bgp_ospf_page():
    rid    = _rid()
    router = db.get_router(rid) if rid else None
    return render_template("bgp_ospf.html", active_page="bgp_ospf", router=router)


@main_bp.route("/report")
@login_required
def report_page():
    return render_template("report.html", active_page="report")


@main_bp.route("/compare")
@login_required
def compare_page():
    routers = db.get_all_routers() if not db.needs_setup() else []
    return render_template("compare.html", active_page="compare", routers=routers)


@main_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", active_page="dashboard")


@main_bp.route("/topology")
@login_required
def topology():
    return render_template("topology.html", active_page="topology")
