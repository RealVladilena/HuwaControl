"""
Blueprint api — tous les endpoints /api/*.
"""
import csv
import io
import json
import logging
import time
from datetime import datetime

from flask import Blueprint, Response, jsonify, request, session
from flask_login import current_user, login_required

import database as db
import snmp_collector as collector
import notifications
import reports
import config
from utils import fmt_uptime, fmt_bps, fmt_pps, _rid
from scheduler_utils import scheduler, _start_job, _stop_job
from permissions import require_router_access

log = logging.getLogger("api")

api_bp = Blueprint("api", __name__)


# ── Routeurs ─────────────────────────────────────────────────────────────────

@api_bp.route("/api/routers", methods=["GET"])
@login_required
def api_routers_list():
    return jsonify(db.get_all_routers())


@api_bp.route("/api/routers", methods=["POST"])
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


@api_bp.route("/api/routers/<int:rid>", methods=["GET"])
@login_required
@require_router_access(write=False)
def api_routers_get(rid):
    r = db.get_router(rid)
    return jsonify(r) if r else ("", 404)


@api_bp.route("/api/routers/<int:rid>", methods=["PUT"])
@login_required
@require_router_access(write=True)
def api_routers_update(rid):
    d = request.json or {}
    router = db.update_router(rid, **d)
    if not router:
        return ("", 404)
    _start_job(router)
    return jsonify(router)


@api_bp.route("/api/routers/<int:rid>", methods=["DELETE"])
@login_required
@require_router_access(write=True)
def api_routers_delete(rid):
    _stop_job(rid)
    db.delete_router(rid)
    if session.get("router_id") == rid:
        session.pop("router_id", None)
    return ("", 204)


@api_bp.route("/api/routers/<int:rid>/poll", methods=["POST"])
@login_required
@require_router_access(write=True)
def api_routers_poll(rid):
    router = db.get_router(rid)
    if not router:
        return ("", 404)
    try:
        collector.poll(router)
        return jsonify({"ok": True, "ts": int(time.time())})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── Données ──────────────────────────────────────────────────────────────────

@api_bp.route("/api/status")
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


@api_bp.route("/api/interfaces")
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
            "alias":        alias,
            "display_name": f"{alias} ({iface['if_name']})" if alias else iface["if_name"],
            "in_bps_fmt":   fmt_bps(latest_bps.get("in_bps")),
            "out_bps_fmt":  fmt_bps(latest_bps.get("out_bps")),
            "in_pps_fmt":   fmt_pps(latest_bps.get("in_pps")),
            "out_pps_fmt":  fmt_pps(latest_bps.get("out_pps")),
            "in_pps":       latest_bps.get("in_pps"),
            "out_pps":      latest_bps.get("out_pps"),
        })
    return jsonify(result)


@api_bp.route("/api/lte")
@login_required
def api_lte():
    rid = _rid()
    if not rid:
        return jsonify(None)
    hours        = request.args.get("hours", 1, type=int)
    latest       = db.get_lte_latest(rid)
    history      = db.get_lte_history(rid, hours=hours)
    radios       = db.get_wifi_radio_latest(rid)
    sys_latest   = db.get_latest_system(rid)
    fault_status = sys_latest.get("fault_status") if sys_latest else None
    return jsonify({"latest": latest, "history": history, "wifi_radios": radios,
                    "fault_status": fault_status})


@api_bp.route("/api/interfaces/<int:if_index>/bps")
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


@api_bp.route("/api/performance")
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


@api_bp.route("/api/history")
@login_required
def api_history():
    rid  = _rid()
    days = request.args.get("days", 30, type=int)
    rows = db.get_system_history_days(rid, days=days) if rid else []
    return jsonify({
        "labels":   [r["hour"]     for r in rows],
        "cpu_avg":  [r["cpu_avg"]  for r in rows],
        "cpu_max":  [r["cpu_max"]  for r in rows],
        "mem_avg":  [r["mem_avg"]  for r in rows],
        "mem_max":  [r["mem_max"]  for r in rows],
        "temp_avg": [r["temp_avg"] for r in rows],
    })


@api_bp.route("/api/clients")
@login_required
def api_clients():
    rid    = _rid()
    router = db.get_router(rid) if rid else None
    if not router:
        return jsonify([])
    try:
        return jsonify(collector.collect_clients(router))
    except Exception as e:
        log.error("collect_clients: %s", e)
        return jsonify([])


@api_bp.route("/api/wifi")
@login_required
def api_wifi():
    rid    = _rid()
    router = db.get_router(rid) if rid else None
    if not router:
        return jsonify({"interfaces": [], "clients": []})
    try:
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
        try:
            wifi_clients = collector.collect_wifi_clients(router)
        except Exception:
            wifi_clients = []
        return jsonify({"interfaces": wifi_ifaces, "clients": wifi_clients})
    except Exception as e:
        log.error("api_wifi: %s", e)
        return jsonify({"interfaces": [], "clients": []})


@api_bp.route("/api/events")
@login_required
def api_events():
    rid   = request.args.get("router_id", type=int) or None
    limit = request.args.get("limit", 200, type=int)
    return jsonify(db.get_events(router_id=rid, limit=limit))


@api_bp.route("/api/events/daily")
@login_required
def api_events_daily():
    rid  = request.args.get("router_id", type=int) or _rid() or None
    days = request.args.get("days", 60, type=int)
    return jsonify(db.get_events_daily(router_id=rid, days=days))


@api_bp.route("/api/vpn")
@login_required
def api_vpn():
    rid    = _rid()
    router = db.get_router(rid) if rid else None
    if not router:
        return jsonify({"tunnels": [], "ike_sas": []})
    ifaces  = db.get_interfaces_latest(rid)
    vpn_kw  = ("tunnel", "gre", "ipsec", "l2tp", "pppoe", "vpn")
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


# ── Discord webhooks ──────────────────────────────────────────────────────────

@api_bp.route("/api/discord", methods=["GET"])
@login_required
def api_discord_list():
    return jsonify(db.get_discord_webhooks())


@api_bp.route("/api/discord", methods=["POST"])
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


@api_bp.route("/api/discord/<int:wh_id>", methods=["PUT"])
@login_required
def api_discord_update(wh_id):
    if not current_user.is_admin:
        return ("", 403)
    d  = request.json or {}
    wh = db.update_discord_webhook(wh_id, **d)
    return jsonify(wh) if wh else ("", 404)


@api_bp.route("/api/discord/<int:wh_id>", methods=["DELETE"])
@login_required
def api_discord_delete(wh_id):
    if not current_user.is_admin:
        return ("", 403)
    db.delete_discord_webhook(wh_id)
    return ("", 204)


@api_bp.route("/api/discord/<int:wh_id>/test", methods=["POST"])
@login_required
def api_discord_test(wh_id):
    webhooks = db.get_discord_webhooks()
    wh = next((w for w in webhooks if w["id"] == wh_id), None)
    if not wh:
        return ("", 404)
    ok, err = notifications.send_discord_test(wh["url"], wh["name"])
    return jsonify({"ok": ok, "error": err})


# ── Paramètres ────────────────────────────────────────────────────────────────

@api_bp.route("/api/settings", methods=["GET"])
@login_required
def api_settings_get():
    return jsonify(db.get_settings())


@api_bp.route("/api/settings", methods=["POST"])
@login_required
def api_settings_post():
    if not current_user.is_admin:
        return ("", 403)
    d = request.json or {}
    for k, v in d.items():
        db.set_setting(k, str(v))
    return jsonify({"ok": True})


@api_bp.route("/api/events/<int:event_id>/ack", methods=["POST"])
@login_required
def api_event_ack(event_id):
    ok = db.ack_event(event_id, current_user.username)
    if ok:
        db.add_audit(current_user.username, "event_ack",
                     f"Acquittement événement #{event_id}", ip=request.remote_addr)
    return jsonify({"ok": ok})


# ── Audit ─────────────────────────────────────────────────────────────────────

@api_bp.route("/api/audit")
@login_required
def api_audit():
    if not current_user.is_admin:
        return ("", 403)
    limit = request.args.get("limit", 200, type=int)
    return jsonify(db.get_audit(limit=limit))


# ── Telegram bots ─────────────────────────────────────────────────────────────

@api_bp.route("/api/telegram", methods=["GET"])
@login_required
def api_telegram_list():
    return jsonify(db.get_telegram_bots())


@api_bp.route("/api/telegram", methods=["POST"])
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


@api_bp.route("/api/telegram/<int:bot_id>", methods=["PUT"])
@login_required
def api_telegram_update(bot_id):
    if not current_user.is_admin:
        return ("", 403)
    d   = request.json or {}
    bot = db.update_telegram_bot(bot_id, **d)
    return jsonify(bot) if bot else ("", 404)


@api_bp.route("/api/telegram/<int:bot_id>", methods=["DELETE"])
@login_required
def api_telegram_delete(bot_id):
    if not current_user.is_admin:
        return ("", 403)
    db.delete_telegram_bot(bot_id)
    db.add_audit(current_user.username, "telegram_delete",
                 f"Suppression bot Telegram #{bot_id}", ip=request.remote_addr)
    return ("", 204)


@api_bp.route("/api/telegram/<int:bot_id>/test", methods=["POST"])
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


# ── Email test ────────────────────────────────────────────────────────────────

@api_bp.route("/api/email/test", methods=["POST"])
@login_required
def api_email_test():
    if not current_user.is_admin:
        return ("", 403)
    cfg      = db.get_settings()
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


# ── Cibles ping ───────────────────────────────────────────────────────────────

@api_bp.route("/api/ping-targets", methods=["GET"])
@login_required
def api_ping_targets_list():
    rid = request.args.get("router_id", type=int) or None
    return jsonify(db.get_ping_targets(router_id=rid))


@api_bp.route("/api/ping-targets", methods=["POST"])
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


@api_bp.route("/api/ping-targets/<int:tid>", methods=["PUT"])
@login_required
def api_ping_targets_update(tid):
    if not current_user.is_admin:
        return ("", 403)
    d      = request.json or {}
    target = db.update_ping_target(tid, **d)
    return jsonify(target) if target else ("", 404)


@api_bp.route("/api/ping-targets/<int:tid>", methods=["DELETE"])
@login_required
def api_ping_targets_delete(tid):
    if not current_user.is_admin:
        return ("", 403)
    db.delete_ping_target(tid)
    return ("", 204)


@api_bp.route("/api/ping/<int:tid>/history")
@login_required
def api_ping_history(tid):
    hours = request.args.get("hours", 24, type=int)
    rows  = db.get_ping_history(tid, hours=hours)
    return jsonify({
        "labels":  [datetime.fromtimestamp(r["ts"]).strftime("%H:%M") for r in rows],
        "rtt":     [r["rtt_ms"]  for r in rows],
        "success": [r["success"] for r in rows],
    })


@api_bp.route("/api/ping/<int:tid>/sla")
@login_required
def api_ping_sla(tid):
    hours = request.args.get("hours", 24, type=int)
    return jsonify(db.get_sla_stats(tid, hours=hours))


# ── Table de routage ──────────────────────────────────────────────────────────

@api_bp.route("/api/routing-table")
@login_required
def api_routing_table():
    rid    = _rid()
    router = db.get_router(rid) if rid else None
    if not router:
        return jsonify([])
    try:
        return jsonify(collector.collect_routing_table(router))
    except Exception as e:
        log.error("collect_routing_table: %s", e)
        return jsonify([])


# ── Seuils par interface ──────────────────────────────────────────────────────

@api_bp.route("/api/thresholds")
@login_required
def api_thresholds_list():
    rid = _rid()
    if not rid:
        return jsonify([])
    return jsonify(db.get_interface_thresholds(rid))


@api_bp.route("/api/thresholds", methods=["POST"])
@login_required
def api_thresholds_set():
    if not current_user.is_admin:
        return ("", 403)
    d        = request.json or {}
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


@api_bp.route("/api/thresholds/<int:if_index>", methods=["DELETE"])
@login_required
def api_thresholds_delete(if_index):
    if not current_user.is_admin:
        return ("", 403)
    rid = _rid()
    if rid:
        db.delete_interface_threshold(rid, if_index)
    return ("", 204)


# ── Alias d'interfaces ────────────────────────────────────────────────────────

@api_bp.route("/api/aliases")
@login_required
def api_aliases_list():
    rid = _rid()
    if not rid:
        return jsonify({})
    return jsonify(db.get_interface_aliases(rid))


@api_bp.route("/api/aliases", methods=["POST"])
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


# ── Rapports ──────────────────────────────────────────────────────────────────

@api_bp.route("/api/reports/send", methods=["POST"])
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


@api_bp.route("/api/reports/latest")
@login_required
def api_reports_latest():
    try:
        return jsonify(reports.build_report())
    except Exception as e:
        log.error("api_reports_latest: %s", e)
        return jsonify({"error": str(e)}), 500


# ── Exports CSV ───────────────────────────────────────────────────────────────

@api_bp.route("/api/export/events")
@login_required
def api_export_events():
    rid  = request.args.get("router_id", type=int) or None
    rows = db.get_events(router_id=rid, limit=10000)
    buf  = io.StringIO()
    w    = csv.writer(buf)
    w.writerow(["id", "ts", "datetime", "level", "category", "router",
                "title", "message", "acked"])
    for r in rows:
        w.writerow([
            r["id"], r["ts"],
            datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M:%S"),
            r["level"], r["category"], r.get("router_name", ""),
            r["title"], r.get("message", ""), r.get("acked", False),
        ])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=events.csv"})


@api_bp.route("/api/export/interfaces")
@login_required
def api_export_interfaces():
    rid    = _rid()
    ifaces = db.get_interfaces_latest(rid) if rid else []
    buf    = io.StringIO()
    w      = csv.writer(buf)
    w.writerow(["if_index", "if_name", "if_status", "speed_mbps",
                "in_octets", "out_octets", "in_errors", "out_errors",
                "in_ucast_pkts", "out_ucast_pkts"])
    for r in ifaces:
        w.writerow([r["if_index"], r["if_name"], r["if_status"], r["speed_mbps"],
                    r["in_octets"], r["out_octets"], r["in_errors"], r["out_errors"],
                    r["in_ucast_pkts"], r["out_ucast_pkts"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=interfaces.csv"})


@api_bp.route("/api/export/performance")
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


@api_bp.route("/api/history/iface/<int:if_index>")
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


# ── Utilisateurs ──────────────────────────────────────────────────────────────

@api_bp.route("/api/users/password", methods=["POST"])
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


@api_bp.route("/api/users", methods=["POST"])
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


@api_bp.route("/api/users/<int:uid>", methods=["DELETE"])
@login_required
def api_delete_user(uid):
    if not current_user.is_admin:
        return ("", 403)
    if uid == int(current_user.id):
        return jsonify({"error": "Impossible de supprimer son propre compte"}), 400
    db.delete_user(uid)
    return ("", 204)


@api_bp.route("/api/users/<int:uid>/perms", methods=["GET"])
@login_required
def api_user_perms_get(uid):
    if not current_user.is_admin:
        return ("", 403)
    return jsonify(db.get_user_router_perms(uid))


@api_bp.route("/api/users/<int:uid>/perms", methods=["POST"])
@login_required
def api_user_perms_set(uid):
    if not current_user.is_admin:
        return ("", 403)
    d         = request.json or {}
    router_id = d.get("router_id")
    can_write = bool(d.get("can_write", False))
    if not router_id:
        return jsonify({"error": "router_id requis"}), 400
    db.set_user_router_perm(uid, router_id, can_write)
    return jsonify({"ok": True})


@api_bp.route("/api/users/<int:uid>/perms/<int:rid>", methods=["DELETE"])
@login_required
def api_user_perms_delete(uid, rid):
    if not current_user.is_admin:
        return ("", 403)
    db.delete_user_router_perm(uid, rid)
    return ("", 204)


@api_bp.route("/api/users/<int:uid>/email", methods=["PUT"])
@login_required
def api_user_email(uid):
    if not current_user.is_admin:
        return ("", 403)
    email = (request.json or {}).get("email", "").strip()
    db.set_user_email(uid, email or None)
    return jsonify({"ok": True})


# ── Syslogs ───────────────────────────────────────────────────────────────────

@api_bp.route("/api/syslogs")
@login_required
def api_syslogs():
    limit    = request.args.get("limit", 200, type=int)
    offset   = request.args.get("offset", 0, type=int)
    severity = request.args.get("severity", 7, type=int)
    search   = request.args.get("q", "")
    rows  = db.get_syslogs(limit=limit, severity_max=severity,
                           search=search, offset=offset)
    total = db.count_syslogs(severity_max=severity, search=search)
    return jsonify({"rows": rows, "total": total})


@api_bp.route("/api/syslogs/stats")
@login_required
def api_syslogs_stats():
    hours = request.args.get("hours", 24, type=int)
    try:
        return jsonify(db.get_syslog_daily_stats(hours=hours))
    except Exception as e:
        log.error("api_syslogs_stats: %s", e)
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/syslogs", methods=["DELETE"])
@login_required
def api_syslogs_purge():
    if not current_user.is_admin:
        return ("", 403)
    days = request.args.get("days", 30, type=int)
    db.purge_syslogs(days=days)
    return jsonify({"ok": True})


@api_bp.route("/api/export/syslogs")
@login_required
def api_export_syslogs():
    rows = db.get_syslogs(limit=50000, severity_max=7)
    buf  = io.StringIO()
    buf.write("\ufeff")
    w = csv.writer(buf)
    w.writerow(["ts", "datetime", "source_ip", "severity", "facility",
                "hostname", "program", "message"])
    for r in rows:
        w.writerow([
            r["ts"],
            datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M:%S") if r["ts"] else "",
            r.get("source_ip", ""), r.get("severity", ""), r.get("facility", ""),
            r.get("hostname", ""), r.get("program", ""), r.get("message", ""),
        ])
    return Response(buf.getvalue(), mimetype="text/csv;charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=syslogs.csv"})


# ── Acquittement en masse ─────────────────────────────────────────────────────

@api_bp.route("/api/events/ack-all", methods=["POST"])
@login_required
def api_events_ack_all():
    rid = (request.json or {}).get("router_id") or _rid() or None
    n   = db.ack_all_events(router_id=rid, username=current_user.username)
    db.add_audit(current_user.username, "ack_all_events",
                 f"router_id={rid} — {n} événements acquittés")
    return jsonify({"ok": True, "count": n})


# ── ARP historique ────────────────────────────────────────────────────────────

@api_bp.route("/api/arp")
@login_required
def api_arp():
    rid   = _rid()
    limit = request.args.get("limit", 500, type=int)
    rows  = db.get_arp_history(rid, limit=limit) if rid else []
    return jsonify(rows)


@api_bp.route("/api/export/arp")
@login_required
def api_export_arp():
    rid  = _rid()
    rows = db.get_arp_history(rid, limit=50000) if rid else []
    buf  = io.StringIO()
    buf.write("\ufeff")
    w = csv.writer(buf)
    w.writerow(["mac", "ip", "first_seen", "last_seen",
                "first_seen_dt", "last_seen_dt"])
    for r in rows:
        w.writerow([
            r["mac"], r["ip"], r["first_seen"], r["last_seen"],
            datetime.fromtimestamp(r["first_seen"]).strftime("%Y-%m-%d %H:%M:%S"),
            datetime.fromtimestamp(r["last_seen"]).strftime("%Y-%m-%d %H:%M:%S"),
        ])
    return Response(buf.getvalue(), mimetype="text/csv;charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=arp_history.csv"})


# ── DHCP leases ───────────────────────────────────────────────────────────────

@api_bp.route("/api/dhcp")
@login_required
def api_dhcp():
    rid    = _rid()
    router = db.get_router(rid) if rid else None
    if not router:
        return jsonify([])
    try:
        return jsonify(collector.collect_dhcp_leases(router))
    except Exception as e:
        log.error("api_dhcp: %s", e)
        return jsonify([])


# ── BGP / OSPF ────────────────────────────────────────────────────────────────

@api_bp.route("/api/bgp")
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


@api_bp.route("/api/ospf")
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


# ── Backup / Restore ──────────────────────────────────────────────────────────

@api_bp.route("/api/backup")
@login_required
def api_backup():
    if not current_user.is_admin:
        return ("", 403)
    routers      = db.get_all_routers()
    settings     = db.get_settings()
    aliases      = {r["id"]: db.get_interface_aliases(r["id"]) for r in routers}
    ping_targets = db.get_ping_targets()
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
        json.dumps(backup, indent=2, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=huwacontrol_backup.json"}
    )


@api_bp.route("/api/restore", methods=["POST"])
@login_required
def api_restore():
    if not current_user.is_admin:
        return ("", 403)
    try:
        data     = request.json or {}
        restored = {"settings": 0, "ping_targets": 0}
        for k, v in (data.get("settings") or {}).items():
            db.set_setting(k, v)
            restored["settings"] += 1
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


# ── Fenêtres de maintenance ───────────────────────────────────────────────────

@api_bp.route("/api/maintenance", methods=["GET"])
@login_required
def api_maintenance_list():
    rid = request.args.get("router_id", type=int) or None
    return jsonify(db.get_maintenance_windows(rid))


@api_bp.route("/api/maintenance", methods=["POST"])
@login_required
def api_maintenance_create():
    if not current_user.is_admin:
        return ("", 403)
    d        = request.json or {}
    start_ts = d.get("start_ts")
    end_ts   = d.get("end_ts")
    if not start_ts or not end_ts:
        return jsonify({"error": "start_ts et end_ts requis"}), 400
    win = db.create_maintenance_window(
        router_id=d.get("router_id"),
        start_ts=int(start_ts),
        end_ts=int(end_ts),
        description=d.get("description", ""),
        created_by=current_user.username,
    )
    db.add_audit(current_user.username, "maintenance_create",
                 f"router={d.get('router_id')} {d.get('description', '')}",
                 ip=request.remote_addr)
    return jsonify(win), 201


@api_bp.route("/api/maintenance/<int:wid>", methods=["DELETE"])
@login_required
def api_maintenance_delete(wid):
    if not current_user.is_admin:
        return ("", 403)
    db.delete_maintenance_window(wid)
    db.add_audit(current_user.username, "maintenance_delete",
                 f"window_id={wid}", ip=request.remote_addr)
    return ("", 204)


# ── OIDs personnalisés ────────────────────────────────────────────────────────

@api_bp.route("/api/custom-oids")
@login_required
def api_custom_oids_list():
    rid = _rid()
    if not rid:
        return jsonify([])
    return jsonify(db.get_custom_oid_polls(rid))


@api_bp.route("/api/custom-oids", methods=["POST"])
@login_required
def api_custom_oids_create():
    if not current_user.is_admin:
        return ("", 403)
    d   = request.json or {}
    rid = d.get("router_id") or _rid()
    if not rid or not d.get("oid") or not d.get("label"):
        return jsonify({"error": "router_id, oid et label requis"}), 400
    poll = db.create_custom_oid_poll(
        router_id=rid,
        oid=d["oid"],
        label=d["label"],
        unit=d.get("unit", ""),
    )
    return jsonify(poll), 201


@api_bp.route("/api/custom-oids/<int:poll_id>", methods=["PUT"])
@login_required
def api_custom_oids_update(poll_id):
    if not current_user.is_admin:
        return ("", 403)
    d    = request.json or {}
    poll = db.update_custom_oid_poll(poll_id, **d)
    return jsonify(poll) if poll else ("", 404)


@api_bp.route("/api/custom-oids/<int:poll_id>", methods=["DELETE"])
@login_required
def api_custom_oids_delete(poll_id):
    if not current_user.is_admin:
        return ("", 403)
    db.delete_custom_oid_poll(poll_id)
    return ("", 204)


@api_bp.route("/api/custom-oids/<int:poll_id>/values")
@login_required
def api_custom_oids_values(poll_id):
    hours = request.args.get("hours", 24, type=int)
    rows  = db.get_custom_oid_values(poll_id, hours=hours)
    return jsonify({
        "labels": [datetime.fromtimestamp(r["ts"]).strftime("%H:%M") for r in rows],
        "values": [r["value_num"] if r["value_num"] is not None else r["value_text"]
                   for r in rows],
    })


# ── SLA WAN ───────────────────────────────────────────────────────────────────

@api_bp.route("/api/wan-sla")
@login_required
def api_wan_sla():
    rid   = _rid()
    hours = request.args.get("hours", 24, type=int)
    if not rid:
        return jsonify([])
    return jsonify(db.get_wan_sla_list(rid, hours=hours))


# ── Totaux bande passante ─────────────────────────────────────────────────────

@api_bp.route("/api/bandwidth-totals")
@login_required
def api_bandwidth_totals():
    rid         = _rid()
    period_type = request.args.get("period", "daily")
    if not rid:
        return jsonify([])
    return jsonify(db.get_bandwidth_totals(rid, period_type=period_type))


# ── WiFi client history ───────────────────────────────────────────────────────

@api_bp.route("/api/wifi/clients/history")
@login_required
def api_wifi_clients_history():
    rid   = _rid()
    hours = request.args.get("hours", 24, type=int)
    if not rid:
        return jsonify([])
    return jsonify(db.get_wifi_client_history(rid, hours=hours))


# ── Dashboard multi-routeurs ──────────────────────────────────────────────────

@api_bp.route("/api/dashboard")
@login_required
def api_dashboard():
    routers = db.get_enabled_routers()
    result  = []
    for r in routers:
        rid      = r["id"]
        sys_data = db.get_latest_system(rid)
        ifaces   = db.get_interfaces_latest(rid)
        events   = db.get_events(router_id=rid, limit=100)
        recent_ev = [e for e in events if not e.get("acked")]

        ifaces_up   = sum(1 for i in ifaces if i.get("if_status") == 1)
        ifaces_down = len(ifaces) - ifaces_up
        errors      = sum(1 for e in recent_ev if e["level"] == "error")
        warnings    = sum(1 for e in recent_ev if e["level"] == "warning")

        if errors > 0 or ifaces_down > 2:
            status = "error"
        elif warnings > 0 or ifaces_down > 0:
            status = "warn"
        else:
            status = "ok"

        wan_sla  = db.get_wan_sla_list(rid, hours=24)
        best_sla = min((s["sla"] for s in wan_sla if s["sla"] is not None), default=None)

        result.append({
            "id":             rid,
            "name":           r["name"],
            "ip":             r["ip"],
            "status":         status,
            "cpu":            sys_data.get("cpu_usage"),
            "mem":            sys_data.get("mem_usage"),
            "temp":           sys_data.get("temperature"),
            "uptime":         fmt_uptime(sys_data.get("sys_uptime")),
            "ifaces_up":      ifaces_up,
            "ifaces_total":   len(ifaces),
            "errors":         errors,
            "warnings":       warnings,
            "wan_sla":        best_sla,
            "last_seen":      sys_data.get("ts"),
            "in_maintenance": db.is_in_maintenance(rid),
        })
    return jsonify(result)
