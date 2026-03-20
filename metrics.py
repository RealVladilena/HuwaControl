"""
Endpoint Prometheus /metrics — exposé uniquement si un token bearer est configuré.

Configuration (settings DB ou variable d'env) :
  metrics_enabled = "1"        — active l'endpoint (défaut : "0")
  metrics_token   = "<token>"  — bearer token requis dans Authorization header

Format : texte Prometheus (OpenMetrics compatible).
"""
import logging
import os
import time

from flask import Blueprint, Response, request

import database as db

log = logging.getLogger("metrics")

metrics_bp = Blueprint("metrics", __name__)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_cfg() -> dict:
    try:
        return db.get_settings()
    except Exception:
        return {}


def _authorized(cfg: dict) -> bool:
    """Vérifie le bearer token si configuré."""
    token = cfg.get("metrics_token") or os.getenv("METRICS_TOKEN", "")
    if not token:
        # Aucun token configuré → accès refusé par défaut (sécurité)
        return False
    auth = request.headers.get("Authorization", "")
    return auth == f"Bearer {token}"


# ── Collecte des métriques ────────────────────────────────────────────────────

def _collect() -> str:
    lines: list[str] = []

    def gauge(name: str, value, labels: dict | None = None, help_text: str = "") -> None:
        if value is None:
            return
        lbl = ""
        if labels:
            parts = ",".join(f'{k}="{v}"' for k, v in labels.items())
            lbl = "{" + parts + "}"
        if help_text:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name}{lbl} {value}")

    routers = db.get_all_routers()

    for r in routers:
        rid   = r["id"]
        rname = r["name"]
        rip   = r["ip"]

        # ── Système ──────────────────────────────────────────────────────────
        sys_data = db.get_latest_system(rid) or {}
        lbl = {"router": rname, "ip": rip}

        gauge("huwa_cpu_usage_percent",
              sys_data.get("cpu_usage"), lbl,
              "CPU usage percent of the router")
        gauge("huwa_mem_usage_percent",
              sys_data.get("mem_usage"), lbl,
              "Memory usage percent of the router")
        gauge("huwa_temperature_celsius",
              sys_data.get("temperature"), lbl,
              "Temperature of the router in Celsius")
        gauge("huwa_uptime_seconds",
              int(sys_data["sys_uptime"]) // 100 if sys_data.get("sys_uptime") else None,
              lbl, "System uptime in seconds")

        # ── Interfaces ───────────────────────────────────────────────────────
        ifaces = db.get_interfaces_latest(rid)
        for iface in ifaces:
            ilbl = {
                "router":   rname,
                "ip":       rip,
                "if_index": str(iface["if_index"]),
                "if_name":  iface.get("if_name", ""),
            }
            gauge("huwa_interface_status",
                  1 if iface.get("if_status") == 1 else 0, ilbl,
                  "Interface operational status (1=up, 0=down)")
            bps_rows   = db.get_bps_history(rid, iface["if_index"], hours=1)
            latest_bps = bps_rows[-1] if bps_rows else {}
            gauge("huwa_interface_in_bps",
                  latest_bps.get("in_bps"),  ilbl, "Interface inbound bits per second")
            gauge("huwa_interface_out_bps",
                  latest_bps.get("out_bps"), ilbl, "Interface outbound bits per second")
            gauge("huwa_interface_in_errors_total",
                  iface.get("in_errors"),  ilbl, "Interface inbound error count")
            gauge("huwa_interface_out_errors_total",
                  iface.get("out_errors"), ilbl, "Interface outbound error count")

        # ── Événements non acquittés ──────────────────────────────────────────
        events   = db.get_events(router_id=rid, limit=500)
        unacked  = [e for e in events if not e.get("acked")]
        for lvl in ("error", "warning", "info"):
            count = sum(1 for e in unacked if e["level"] == lvl)
            gauge("huwa_events_unacked_total", count,
                  {"router": rname, "ip": rip, "level": lvl},
                  "Count of unacknowledged events by level")

        # ── WAN SLA ───────────────────────────────────────────────────────────
        wan_sla = db.get_wan_sla_list(rid, hours=24)
        if wan_sla:
            best_sla = min((s["sla"] for s in wan_sla if s["sla"] is not None), default=None)
            gauge("huwa_wan_sla_percent", best_sla, lbl,
                  "Best WAN SLA percent over last 24h")

    # ── Scrape timestamp ─────────────────────────────────────────────────────
    lines.append(f"# HELP huwa_scrape_time_seconds Time of last metrics scrape")
    lines.append(f"# TYPE huwa_scrape_time_seconds gauge")
    lines.append(f"huwa_scrape_time_seconds {time.time():.3f}")

    return "\n".join(lines) + "\n"


# ── Route ─────────────────────────────────────────────────────────────────────

@metrics_bp.route("/metrics")
def metrics():
    cfg = _get_cfg()

    if cfg.get("metrics_enabled", "0") != "1":
        return Response("Metrics endpoint disabled", status=404,
                        mimetype="text/plain")

    if not _authorized(cfg):
        return Response("Unauthorized", status=401,
                        mimetype="text/plain",
                        headers={"WWW-Authenticate": 'Bearer realm="metrics"'})

    try:
        body = _collect()
        return Response(body, status=200,
                        mimetype="text/plain; version=0.0.4; charset=utf-8")
    except Exception as e:
        log.error("metrics collection error: %s", e)
        return Response(f"# collection error: {e}\n", status=500,
                        mimetype="text/plain")
