"""
Rapports quotidiens — HuwaControl.
Génère et envoie un rapport journalier complet via Discord et/ou Telegram.
"""
import logging
import time

import database as db
import notifications

log = logging.getLogger("reports")


def _fmt_bps(bps):
    if bps is None:
        return "N/A"
    if bps >= 1e9:
        return f"{bps/1e9:.2f} Gbps"
    if bps >= 1e6:
        return f"{bps/1e6:.2f} Mbps"
    if bps >= 1e3:
        return f"{bps/1e3:.1f} Kbps"
    return f"{int(bps)} bps"


def build_report() -> dict:
    """Génère le contenu du rapport. Retourne {title, description, fields}."""
    today_start = int(time.time()) - 86400
    routers     = db.get_enabled_routers()

    all_errors   = 0
    all_warnings = 0
    router_lines = []

    for router in routers:
        rid    = router["id"]
        rname  = router["name"]
        sys    = db.get_latest_system(rid)
        ifaces = db.get_interfaces_latest(rid)
        events = db.get_events(router_id=rid, limit=2000)
        day_ev = [e for e in events if e["ts"] >= today_start]

        errors   = sum(1 for e in day_ev if e["level"] == "error")
        warnings = sum(1 for e in day_ev if e["level"] == "warning")
        all_errors   += errors
        all_warnings += warnings

        ifaces_up   = sum(1 for i in ifaces if i.get("if_status") == 1)
        ifaces_down = len(ifaces) - ifaces_up
        cpu  = sys.get("cpu_usage")
        mem  = sys.get("mem_usage")
        temp = sys.get("temperature")

        status_icon = "🟢" if ifaces_down == 0 else "🟡" if ifaces_down <= 2 else "🔴"
        line = f"{status_icon} **{rname}**"
        if cpu is not None:
            line += f" — CPU {cpu:.0f}% / RAM {mem:.0f}%" if mem else f" — CPU {cpu:.0f}%"
        if temp is not None:
            line += f" / {temp:.0f}°C"
        line += f"\n  Interfaces : {ifaces_up}/{len(ifaces)} UP"
        if ifaces_down:
            down_names = [i.get("if_name", f"if{i['if_index']}")
                          for i in ifaces if i.get("if_status") != 1]
            line += f" ⚠️ DOWN: {', '.join(down_names[:3])}"
        if errors or warnings:
            line += f"\n  ⚠️ {warnings} alertes, 🚨 {errors} erreurs"
        router_lines.append(line)

    # SLA ping
    ping_lines = []
    try:
        targets = db.get_ping_targets(enabled_only=True)
        for t in targets:
            sla = db.get_sla_stats(t["id"], hours=24)
            if sla["sla"] is not None:
                icon = "🟢" if sla["sla"] >= 99 else "🟡" if sla["sla"] >= 95 else "🔴"
                line = f"{icon} **{t['label']}** ({t['host']}) — SLA {sla['sla']}%"
                if sla["avg_rtt"]:
                    line += f" · RTT moy {sla['avg_rtt']}ms"
                ping_lines.append(line)
    except Exception as e:
        log.error("SLA report: %s", e)

    description = "\n".join(router_lines) if router_lines else "Aucun routeur actif."
    if ping_lines:
        description += "\n\n**Ping / Latence :**\n" + "\n".join(ping_lines)

    # Stats syslog 24h
    syslog_section = ""
    try:
        sl = db.get_syslog_daily_stats(hours=24)
        if sl["total"] > 0:
            syslog_section = (
                f"\n\n**Syslog 24h :** {sl['total']} messages — "
                f"🚨 {sl['errors']} erreur{'s' if sl['errors']!=1 else ''} / "
                f"⚠️ {sl['warnings']} avertissement{'s' if sl['warnings']!=1 else ''}"
            )
            if sl["wifi_connect"] or sl["wifi_disconnect"]:
                syslog_section += (
                    f"\n📶 WiFi : {sl['wifi_connect']} connexion{'s' if sl['wifi_connect']!=1 else ''} / "
                    f"{sl['wifi_disconnect']} déconnexion{'s' if sl['wifi_disconnect']!=1 else ''}"
                )
            if sl["top_programs"]:
                progs = ", ".join(f"{p['program']} ({p['count']})" for p in sl["top_programs"][:3])
                syslog_section += f"\n📋 Top programmes : {progs}"
        description += syslog_section
    except Exception as e:
        log.error("syslog stats report: %s", e)

    fields = [
        {"name": "Routeurs",      "value": str(len(routers)),    "inline": True},
        {"name": "Alertes 24h",   "value": str(all_warnings),    "inline": True},
        {"name": "Erreurs 24h",   "value": str(all_errors),      "inline": True},
    ]
    if ping_lines:
        fields.append({"name": "Cibles ping", "value": str(len(ping_lines)), "inline": True})
    try:
        sl = db.get_syslog_daily_stats(hours=24)
        if sl["total"] > 0:
            fields.append({"name": "Syslog 24h",  "value": str(sl["total"]),   "inline": True})
        if sl["wifi_connect"]:
            fields.append({"name": "WiFi conn.",   "value": str(sl["wifi_connect"]), "inline": True})
    except Exception:
        pass

    title = f"📊 Rapport quotidien — {time.strftime('%d/%m/%Y', time.localtime())}"
    return {"title": title, "description": description, "fields": fields}


def send_daily_report() -> None:
    """Envoie le rapport à tous les canaux de notification actifs."""
    log.info("Génération du rapport quotidien")
    try:
        webhooks = db.get_discord_webhooks(enabled_only=True)
        tg_bots  = db.get_telegram_bots(enabled_only=True)
        if not webhooks and not tg_bots:
            log.info("Aucun canal de notification configuré, rapport ignoré")
            return

        report = build_report()

        for wh in webhooks:
            notifications.send_discord(
                wh["url"], "info",
                report["title"], report["description"],
                fields=report["fields"], router_name=""
            )

        for bot in tg_bots:
            notifications.send_telegram(
                bot["bot_token"], bot["chat_id"],
                "info", report["title"], report["description"], ""
            )

        log.info("Rapport quotidien envoyé (%d Discord, %d Telegram)",
                 len(webhooks), len(tg_bots))

    except Exception as e:
        log.error("send_daily_report: %s", e)
