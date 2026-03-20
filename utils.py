"""
Utilitaires partagés (formatage, helpers de requête).
"""
from flask import request, session
import database as db


def fmt_uptime(ticks):
    if ticks is None:
        return "N/A"
    s = int(ticks) // 100
    d, r = divmod(s, 86400)
    h, r = divmod(r, 3600)
    m = r // 60
    if d >= 1:
        return f"{d}j {h:02d}h"
    if h >= 1:
        return f"{h:02d}h {m:02d}m"
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


def _rid():
    """Récupère router_id depuis les args ou la session."""
    rid = request.args.get("router_id", type=int) or session.get("router_id")
    if not rid:
        routers = db.get_all_routers()
        rid = routers[0]["id"] if routers else None
    return rid


def _active_router_id():
    """Retourne le router_id depuis les args, le cookie ou le premier dispo."""
    rid = request.args.get("router_id", type=int) or session.get("router_id")
    if rid:
        session["router_id"] = rid
        return rid
    routers = db.get_all_routers()
    if routers:
        session["router_id"] = routers[0]["id"]
        return routers[0]["id"]
    return None
