"""
Collecteur de ping/latence — HuwaControl.
Envoie des pings ICMP vers les cibles configurées et stocke les RTT.
"""
import logging
import re
import subprocess
import time

import database as db
import notifications

log = logging.getLogger("ping")

# {target_id: last_known_success}  — pour détecter les transitions up/down
_prev_ping_status: dict = {}
_alert_cooldown:   dict = {}
COOLDOWN_S = 300


def _cooldown_ok(key: str) -> bool:
    now = time.time()
    if now - _alert_cooldown.get(key, 0) > COOLDOWN_S:
        _alert_cooldown[key] = now
        return True
    return False


def ping_host(host: str, count: int = 3, timeout: int = 5) -> tuple[bool, float | None]:
    """
    Ping un hôte, retourne (succès, RTT_moyen_ms).
    Fonctionne sur Linux (requiert iputils-ping dans le container).
    """
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), host],
            capture_output=True, text=True, timeout=timeout * count + 5
        )
        if result.returncode != 0:
            return False, None
        # Extraire le RTT moyen depuis la ligne "rtt min/avg/max/mdev"
        m = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", result.stdout)
        if m:
            return True, float(m.group(1))
        return True, None
    except FileNotFoundError:
        log.warning("ping non disponible — installer iputils-ping dans le container")
        return False, None
    except subprocess.TimeoutExpired:
        return False, None
    except Exception as e:
        log.error("ping_host(%s): %s", host, e)
        return False, None


def poll_ping_target(target: dict) -> None:
    """Poll une cible et stocke le résultat. Envoie des notifications si transition up/down."""
    tid   = target["id"]
    label = target.get("label", target["host"])
    host  = target["host"]

    success, rtt = ping_host(host)
    db.insert_ping_result(tid, rtt, success)

    prev = _prev_ping_status.get(tid)
    if prev is not None and prev != success:
        # Transition
        webhooks = db.get_discord_webhooks(enabled_only=True)
        settings = db.get_settings()
        if success:
            title = f"Hôte joignable : {label}"
            desc  = f"🟢 **{label}** (`{host}`) est de nouveau joignable."
            db.insert_event(None, "info", "ping", title, desc)
            _notify_ping(webhooks, settings, "success", title, desc, label)
        else:
            if _cooldown_ok(f"ping_down_{tid}"):
                title = f"Hôte injoignable : {label}"
                desc  = f"🔴 **{label}** (`{host}`) ne répond plus au ping."
                db.insert_event(None, "error", "ping", title, desc)
                _notify_ping(webhooks, settings, "error", title, desc, label)

    _prev_ping_status[tid] = success


def _notify_ping(webhooks: list, settings: dict, level: str,
                 title: str, desc: str, label: str) -> None:
    for wh in webhooks:
        if (level in ("info", "success") and wh.get("on_info")) or \
           (level == "error" and wh.get("on_error")):
            notifications.send_discord(wh["url"], level, title, desc,
                                       fields=[{"name": "Cible", "value": label, "inline": True}],
                                       router_name="")
    try:
        tg_bots = db.get_telegram_bots(enabled_only=True)
        for bot in tg_bots:
            if (level in ("info", "success") and bot.get("on_info")) or \
               (level == "error" and bot.get("on_error")):
                notifications.send_telegram(
                    bot["bot_token"], bot["chat_id"], level, title, desc, ""
                )
    except Exception as e:
        log.error("Telegram ping notify: %s", e)


def poll_all_targets() -> None:
    """Poll toutes les cibles ping activées."""
    try:
        targets = db.get_ping_targets(enabled_only=True)
        for target in targets:
            try:
                poll_ping_target(target)
            except Exception as e:
                log.error("poll_ping_target(%s): %s", target.get("host"), e)
    except Exception as e:
        log.error("poll_all_targets: %s", e)
