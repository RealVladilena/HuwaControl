"""
Collecteur SNMP multi-routeurs pour HuwaControl.
Chaque routeur est un dict issu de la table `routers`.
"""
import logging
import re
import time

from pysnmp.hlapi import (
    CommunityData, ContextData, ObjectIdentity, ObjectType,
    SnmpEngine, UdpTransportTarget, getCmd, nextCmd,
    UsmUserData,
    usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
    usmDESPrivProtocol, usmAesCfb128Protocol,
    usmNoAuthProtocol, usmNoPrivProtocol,
)

_AUTH_PROTO = {
    "MD5":  usmHMACMD5AuthProtocol,
    "SHA":  usmHMACSHAAuthProtocol,
    "SHA1": usmHMACSHAAuthProtocol,
}
_PRIV_PROTO = {
    "DES":    usmDESPrivProtocol,
    "AES":    usmAesCfb128Protocol,
    "AES128": usmAesCfb128Protocol,
}

import config
import database as db
import notifications

log = logging.getLogger("snmp")

# {(router_id, if_index): (ts, in_octets, out_octets, in_pkts, out_pkts)}
_prev_counters: dict = {}

# {(router_id, if_index): last_known_status}
_prev_if_status: dict = {}

# {alert_key: last_sent_timestamp}  — évite le spam de notifications
_alert_cooldown: dict = {}
COOLDOWN_S = 300   # 5 minutes entre deux mêmes alertes

# {router_id: timestamp when metric first exceeded threshold}
_high_cpu_since:  dict = {}
_high_mem_since:  dict = {}

# {(router_id, peer_ip): state_id}  — suivi BGP/OSPF
_prev_bgp_states:  dict = {}
_prev_ospf_states: dict = {}

# {router_id: set of active WAN if_names}  — suivi failover WAN
_prev_active_wan: dict = {}


def _cooldown_ok(key: str) -> bool:
    now = time.time()
    if now - _alert_cooldown.get(key, 0) > COOLDOWN_S:
        _alert_cooldown[key] = now
        return True
    return False


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _transport(router: dict):
    return UdpTransportTarget(
        (router["ip"], router.get("snmp_port", 161)),
        timeout=5, retries=2,
    )


def _auth_data(router: dict):
    """Retourne CommunityData (v2c) ou UsmUserData (v3) selon la config du routeur."""
    if router.get("snmp_version", 2) == 3:
        username = router.get("snmp_v3_username") or ""
        level    = router.get("snmp_v3_security_level") or "authPriv"
        auth_key = router.get("snmp_v3_auth_password") or ""
        priv_key = router.get("snmp_v3_priv_password") or ""
        auth_proto = _AUTH_PROTO.get(
            (router.get("snmp_v3_auth_protocol") or "SHA").upper(),
            usmHMACSHAAuthProtocol,
        )
        priv_proto = _PRIV_PROTO.get(
            (router.get("snmp_v3_priv_protocol") or "AES").upper(),
            usmAesCfb128Protocol,
        )
        if level == "noAuthNoPriv":
            return UsmUserData(username)
        if level == "authNoPriv":
            return UsmUserData(username, authKey=auth_key, authProtocol=auth_proto)
        return UsmUserData(username,
                           authKey=auth_key,  authProtocol=auth_proto,
                           privKey=priv_key,  privProtocol=priv_proto)
    # SNMPv2c (défaut)
    return CommunityData(router["snmp_community"], mpModel=1)


def snmp_get(router: dict, oid: str):
    try:
        err_ind, err_stat, _, var_binds = next(
            getCmd(SnmpEngine(), _auth_data(router), _transport(router),
                   ContextData(), ObjectType(ObjectIdentity(oid)))
        )
        if err_ind or err_stat:
            log.debug("[%s] GET %s → %s %s", router["name"], oid, err_ind, err_stat)
            return None
        return var_binds[0][1]
    except Exception as e:
        log.error("[%s] snmp_get(%s): %s", router["name"], oid, e)
        return None


def snmp_walk(router: dict, base_oid: str) -> list:
    results = []
    try:
        for err_ind, err_stat, _, var_binds in nextCmd(
            SnmpEngine(), _auth_data(router), _transport(router), ContextData(),
            ObjectType(ObjectIdentity(base_oid)), lexicographicMode=False,
        ):
            if err_ind or err_stat:
                break
            for vb in var_binds:
                results.append((str(vb[0]), vb[1]))
    except Exception as e:
        log.error("[%s] snmp_walk(%s): %s", router["name"], base_oid, e)
    return results


def _int(v):
    try:
        return int(v)
    except Exception:
        return None


def _float(v):
    try:
        return float(v)
    except Exception:
        return None


# ─── Collecte ─────────────────────────────────────────────────────────────────

def collect_system(router: dict) -> dict:
    data = {
        "sys_name":    str(snmp_get(router, config.OID_SYS_NAME)     or ""),
        "sys_descr":   str(snmp_get(router, config.OID_SYS_DESCR)    or ""),
        "sys_uptime":  _int(snmp_get(router, config.OID_SYS_UPTIME)),
        "location":    str(snmp_get(router, config.OID_SYS_LOCATION) or ""),
        "cpu_usage":   None,
        "mem_usage":   None,
        "temperature": None,
    }
    def _best(rows):
        """Retourne la valeur max non-nulle parmi toutes les entités."""
        vals = [_float(v) for _, v in rows if _float(v) is not None]
        non_zero = [v for v in vals if v > 0]
        return max(non_zero) if non_zero else (vals[0] if vals else None)

    data["cpu_usage"]    = _best(snmp_walk(router, config.OID_HW_CPU))
    data["mem_usage"]    = _best(snmp_walk(router, config.OID_HW_MEM))
    data["temperature"]  = _best(snmp_walk(router, config.OID_HW_TEMP))
    data["fault_status"] = _int(_best(snmp_walk(router, config.OID_HW_FAULT_STATUS)))
    return data


def _walk_indexed(router: dict, base_oid: str) -> dict:
    result = {}
    for oid_str, val in snmp_walk(router, base_oid):
        idx = oid_str.rstrip(".").split(".")[-1]
        try:
            result[int(idx)] = val
        except ValueError:
            pass
    return result


def collect_interfaces(router: dict) -> list:
    names    = _walk_indexed(router, config.OID_IF_DESCR)
    statuses = _walk_indexed(router, config.OID_IF_STATUS)
    speeds   = _walk_indexed(router, config.OID_IF_SPEED)
    in_oct   = _walk_indexed(router, config.OID_IF_IN_OCT)
    out_oct  = _walk_indexed(router, config.OID_IF_OUT_OCT)
    in_err   = _walk_indexed(router, config.OID_IF_IN_ERR)
    out_err  = _walk_indexed(router, config.OID_IF_OUT_ERR)
    in_pkt   = _walk_indexed(router, config.OID_IF_IN_PKT)
    if not in_pkt:   # AR651W ne supporte pas les compteurs 64-bit, fallback 32-bit
        in_pkt = _walk_indexed(router, "1.3.6.1.2.1.2.2.1.11")   # ifInUcastPkts
    out_pkt  = _walk_indexed(router, config.OID_IF_OUT_PKT)
    if not out_pkt:
        out_pkt = _walk_indexed(router, "1.3.6.1.2.1.2.2.1.17")  # ifOutUcastPkts
    return [
        {
            "if_index":      idx,
            "if_name":       str(names.get(idx, f"if{idx}")),
            "if_status":     _int(statuses.get(idx)),
            "speed_mbps":    _int(speeds.get(idx)),
            "in_octets":     _int(in_oct.get(idx)),
            "out_octets":    _int(out_oct.get(idx)),
            "in_errors":     _int(in_err.get(idx)),
            "out_errors":    _int(out_err.get(idx)),
            "in_ucast_pkts": _int(in_pkt.get(idx)),
            "out_ucast_pkts":_int(out_pkt.get(idx)),
        }
        for idx in sorted(names.keys())
    ]


def compute_bps(router_id: int, ifaces: list) -> list:
    now = int(time.time())
    bps_rows = []
    for iface in ifaces:
        key      = (router_id, iface["if_index"])
        in_oct   = iface.get("in_octets")
        out_oct  = iface.get("out_octets")
        in_pkts  = iface.get("in_ucast_pkts")
        out_pkts = iface.get("out_ucast_pkts")
        if in_oct is None or out_oct is None:
            continue
        if key in _prev_counters:
            prev_ts, prev_in, prev_out, prev_ip, prev_op = _prev_counters[key]
            delta = now - prev_ts
            if delta > 0:
                in_pps  = max(0, (in_pkts  - prev_ip)  / delta) \
                          if (in_pkts is not None and prev_ip is not None) else None
                out_pps = max(0, (out_pkts - prev_op) / delta) \
                          if (out_pkts is not None and prev_op is not None) else None
                bps_rows.append({
                    "if_index": iface["if_index"],
                    "if_name":  iface.get("if_name"),
                    "in_bps":   max(0, (in_oct  - prev_in)  * 8 / delta),
                    "out_bps":  max(0, (out_oct - prev_out) * 8 / delta),
                    "in_pps":   in_pps,
                    "out_pps":  out_pps,
                })
        _prev_counters[key] = (now, in_oct, out_oct, in_pkts, out_pkts)
    return bps_rows


# ─── Clients connectés (table ARP) ───────────────────────────────────────────

def _fmt_mac(val) -> str:
    """Formate une valeur OctetString en adresse MAC lisible."""
    try:
        raw = bytes(val)
        return ":".join(f"{b:02x}" for b in raw)
    except Exception:
        return str(val)


def _ip_from_oid(oid_str: str, base_oid: str) -> str | None:
    """Extrait l'IP des 4 derniers octets du suffixe OID."""
    suffix = oid_str[len(base_oid):].lstrip(".")
    parts  = suffix.split(".")
    if len(parts) >= 4:
        return ".".join(parts[-4:])
    return None


def collect_clients(router: dict) -> list:
    """Retourne la liste des clients ARP dynamiques (IP + MAC)."""
    macs  = {}
    types = {}

    for oid_str, val in snmp_walk(router, config.OID_ARP_MAC):
        ip = _ip_from_oid(oid_str, config.OID_ARP_MAC)
        if ip:
            macs[ip] = _fmt_mac(val)

    for oid_str, val in snmp_walk(router, config.OID_ARP_TYPE):
        ip = _ip_from_oid(oid_str, config.OID_ARP_TYPE)
        if ip:
            types[ip] = _int(val)

    return [
        {"ip": ip, "mac": mac}
        for ip, mac in macs.items()
        if types.get(ip) == 3          # 3 = dynamic (client actif)
    ]


def collect_wifi_clients(router: dict) -> list:
    """Retourne les clients WiFi via Huawei WLAN MIB (AR651W)."""
    clients = {}
    for oid_str, val in snmp_walk(router, config.OID_WLAN_STA_ENTRY):
        # OID : ...hwWlanApStaInfoEntry.column.mac6bytes
        suffix = oid_str[len(config.OID_WLAN_STA_ENTRY):].lstrip(".")
        parts  = suffix.split(".")
        if len(parts) < 7:
            continue
        col    = parts[0]
        mac    = ":".join(f"{int(b):02x}" for b in parts[1:7])
        entry  = clients.setdefault(mac, {"mac": mac})
        if col == "4":    entry["ssid"]   = str(val)
        elif col == "9":  entry["rssi"]   = _int(val)
        elif col == "14": entry["band"]   = "5GHz" if _int(val) == 2 else "2.4GHz"
    return list(clients.values())


def collect_ike_sas(router: dict) -> list:
    """Tente de lire la table IKE SA Huawei (AR series). Retourne [] si non supporté."""
    sas: dict = {}
    try:
        for oid_str, val in snmp_walk(router, config.OID_HW_IKE_SA_TABLE):
            suffix = oid_str[len(config.OID_HW_IKE_SA_TABLE):].lstrip(".")
            parts  = suffix.split(".")
            if len(parts) < 2:
                continue
            col, idx = parts[0], ".".join(parts[1:])
            entry = sas.setdefault(idx, {})
            if   col == "2": entry["name"]   = str(val)
            elif col == "4": entry["remote"] = _ip_str(val)
            elif col == "6": entry["status"] = _int(val)   # 1=established
    except Exception:
        pass
    return [
        {"name": v.get("name", f"SA-{k}"), "remote": v.get("remote"), "status": v.get("status", 0)}
        for k, v in sas.items()
    ]


# ─── Helpers firmware ────────────────────────────────────────────────────────

def _parse_fw_version(sys_descr: str) -> str | None:
    """Extrait la version VRP Huawei depuis sysDescr.
    Ex: 'Version 5.170 (AR651W V200R021C10SPC600)' → 'V200R021C10SPC600'
    """
    m = re.search(r'(V\d{3}R\d+C\d+(?:SPC\d+)?)', sys_descr or '')
    return m.group(1) if m else None


# ─── Détection événements & notifications ────────────────────────────────────

def _notify(webhooks: list, level: str, title: str, desc: str,
            fields: list | None, router_name: str,
            router_id: int | None = None) -> None:
    # Bypass si routeur en maintenance
    try:
        rid_check = router_id
        if rid_check is None:
            # Tente de retrouver le router_id depuis le nom
            pass
        if rid_check is not None and db.is_in_maintenance(rid_check):
            log.debug("Notification supprimée (maintenance) : %s", title)
            return
    except Exception:
        pass
    settings = db.get_settings()

    # Discord
    for wh in webhooks:
        if (level == "info"    and wh.get("on_info"))    or \
           (level == "warning" and wh.get("on_warning")) or \
           (level == "error"   and wh.get("on_error")):
            notifications.send_discord(wh["url"], level, title, desc,
                                       fields=fields, router_name=router_name)

    # Telegram
    try:
        tg_bots = db.get_telegram_bots(enabled_only=True)
        for bot in tg_bots:
            if (level == "info"    and bot.get("on_info"))    or \
               (level == "warning" and bot.get("on_warning")) or \
               (level == "error"   and bot.get("on_error")):
                notifications.send_telegram(
                    bot["bot_token"], bot["chat_id"],
                    level, title, desc, router_name
                )
    except Exception as e:
        log.error("Telegram notify error: %s", e)

    # Email
    try:
        smtp_host = settings.get("smtp_host", "")
        if smtp_host:
            to_raw = settings.get("smtp_to", "")
            to_addrs = [a.strip() for a in to_raw.split(",") if a.strip()]
            if to_addrs:
                notifications.send_email(
                    smtp_host,
                    int(settings.get("smtp_port", 587)),
                    settings.get("smtp_user", ""),
                    settings.get("smtp_pass", ""),
                    settings.get("smtp_from", ""),
                    to_addrs, level, title, desc, router_name
                )
    except Exception as e:
        log.error("Email notify error: %s", e)


def check_events(router: dict, sys_data: dict,
                 ifaces: list, bps_rows: list) -> None:
    rid       = router["id"]
    rname     = router["name"]
    webhooks  = db.get_discord_webhooks(enabled_only=True)
    settings  = db.get_settings()

    temp_warn  = float(settings.get("alert_temp_warn",  60))
    temp_crit  = float(settings.get("alert_temp_crit",  80))
    bw_warn    = int(  settings.get("alert_bw_warn_pct", 80))

    # 1. Changements d'état des interfaces
    aliases = db.get_interface_aliases(rid)   # {if_index: alias}
    for iface in ifaces:
        idx    = iface["if_index"]
        name   = iface.get("if_name", f"if{idx}")
        alias  = aliases.get(idx, "")
        display = f"{name} ({alias})" if alias else name
        status = iface.get("if_status")
        key    = (rid, idx)
        prev   = _prev_if_status.get(key)

        if prev is not None and prev != status:
            if status == 1:
                title = f"Interface UP : {display}"
                desc  = f"L'interface **{display}** est revenue en ligne sur **{rname}**."
                fields = [{"name": "Routeur",   "value": rname, "inline": True},
                          {"name": "Interface", "value": name,  "inline": True}]
                if alias:
                    fields.append({"name": "Alias", "value": alias, "inline": True})
                db.insert_event(rid, "info", "interface", title, desc)
                _notify(webhooks, "info", title, desc, fields, rname)
            else:
                title = f"Interface DOWN : {display}"
                desc  = f"L'interface **{display}** est passée hors ligne sur **{rname}**."
                fields = [{"name": "Routeur",   "value": rname, "inline": True},
                          {"name": "Interface", "value": name,  "inline": True}]
                if alias:
                    fields.append({"name": "Alias", "value": alias, "inline": True})
                db.insert_event(rid, "warning", "interface", title, desc)
                _notify(webhooks, "warning", title, desc, fields, rname)
        if status is not None:
            _prev_if_status[key] = status

    # 2. Température
    temp = sys_data.get("temperature")
    if temp is not None:
        if temp >= temp_crit and _cooldown_ok(f"temp_crit_{rid}"):
            title = f"Température critique : {temp:.0f}°C"
            desc  = (f"🌡️ La température de **{rname}** a atteint **{temp:.0f}°C** "
                     f"(seuil critique : {temp_crit:.0f}°C).")
            db.insert_event(rid, "error", "temperature", title, desc)
            _notify(webhooks, "error", title, desc,
                    [{"name": "Température", "value": f"{temp:.1f}°C", "inline": True},
                     {"name": "Seuil critique", "value": f"{temp_crit:.0f}°C", "inline": True}],
                    rname)
        elif temp_warn <= temp < temp_crit and _cooldown_ok(f"temp_warn_{rid}"):
            title = f"Température élevée : {temp:.0f}°C"
            desc  = (f"🌡️ La température de **{rname}** est de **{temp:.0f}°C** "
                     f"(seuil d'alerte : {temp_warn:.0f}°C).")
            db.insert_event(rid, "warning", "temperature", title, desc)
            _notify(webhooks, "warning", title, desc,
                    [{"name": "Température", "value": f"{temp:.1f}°C", "inline": True},
                     {"name": "Seuil alerte", "value": f"{temp_warn:.0f}°C", "inline": True}],
                    rname)

    # 3. Bande passante anormale (seuils globaux + seuils par interface)
    speed_map = {i["if_index"]: i.get("speed_mbps") for i in ifaces}
    # Charger seuils per-interface : {if_index: bw_warn_pct}
    try:
        iface_thresholds = {
            t["if_index"]: t["bw_warn_pct"]
            for t in db.get_interface_thresholds(rid)
        }
    except Exception:
        iface_thresholds = {}

    for bps in bps_rows:
        speed_mbps = speed_map.get(bps["if_index"])
        if not speed_mbps or speed_mbps <= 0:
            continue
        speed_bps = speed_mbps * 1_000_000
        in_pct    = (bps.get("in_bps",  0) or 0) / speed_bps * 100
        out_pct   = (bps.get("out_bps", 0) or 0) / speed_bps * 100
        max_pct   = max(in_pct, out_pct)
        # Seuil per-interface en priorité, puis seuil global
        threshold = iface_thresholds.get(bps["if_index"], bw_warn)
        if max_pct >= threshold:
            iname = bps.get("if_name", f"if{bps['if_index']}")
            key   = f"bw_{rid}_{bps['if_index']}"
            if _cooldown_ok(key):
                direc = "IN" if in_pct >= out_pct else "OUT"
                title = f"Trafic élevé : {iname} ({max_pct:.0f}%)"
                desc  = (f"📈 Utilisation à **{max_pct:.0f}%** sur **{iname}** "
                         f"({direc}) — routeur **{rname}**.")
                db.insert_event(rid, "warning", "bandwidth", title, desc)
                _notify(webhooks, "warning", title, desc,
                        [{"name": "Interface", "value": iname,            "inline": True},
                         {"name": "Direction",  "value": direc,            "inline": True},
                         {"name": "Utilisation","value": f"{max_pct:.0f}%","inline": True}],
                        rname)

    # 4. Firmware / version logicielle
    fw_min = (router.get("min_firmware") or "").strip()
    if fw_min:
        fw_cur = _parse_fw_version(sys_data.get("sys_descr", ""))
        if fw_cur and fw_cur != fw_min and _cooldown_ok(f"fw_{rid}"):
            title = f"Firmware obsolète : {fw_cur}"
            desc  = (f"Le routeur **{rname}** tourne sur **{fw_cur}**. "
                     f"Version recommandée : **{fw_min}**.")
            db.insert_event(rid, "warning", "firmware", title, desc)
            _notify(webhooks, "warning", title, desc,
                    [{"name": "Version actuelle",    "value": fw_cur, "inline": True},
                     {"name": "Version recommandée", "value": fw_min, "inline": True}],
                    rname)

    # 5. CPU soutenu élevé
    cpu_thresh = float(settings.get("alert_cpu_warn", 85))
    cpu_usage  = sys_data.get("cpu_usage")
    if cpu_usage is not None:
        if cpu_usage >= cpu_thresh:
            if rid not in _high_cpu_since:
                _high_cpu_since[rid] = time.time()
            elif time.time() - _high_cpu_since[rid] >= 300 and _cooldown_ok(f"cpu_high_{rid}"):
                title = f"CPU soutenu élevé : {cpu_usage:.0f}%"
                desc  = (f"🔥 CPU de **{rname}** à **{cpu_usage:.0f}%** "
                         f"depuis plus de 5 min (seuil : {cpu_thresh:.0f}%).")
                db.insert_event(rid, "warning", "system", title, desc)
                _notify(webhooks, "warning", title, desc,
                        [{"name": "CPU",   "value": f"{cpu_usage:.0f}%",  "inline": True},
                         {"name": "Seuil", "value": f"{cpu_thresh:.0f}%", "inline": True}],
                        rname)
        else:
            _high_cpu_since.pop(rid, None)

    # 6. Mémoire soutenue élevée
    mem_thresh = float(settings.get("alert_mem_warn", 90))
    mem_usage  = sys_data.get("mem_usage")
    if mem_usage is not None:
        if mem_usage >= mem_thresh:
            if rid not in _high_mem_since:
                _high_mem_since[rid] = time.time()
            elif time.time() - _high_mem_since[rid] >= 300 and _cooldown_ok(f"mem_high_{rid}"):
                title = f"Mémoire soutenue élevée : {mem_usage:.0f}%"
                desc  = (f"💾 Mémoire de **{rname}** à **{mem_usage:.0f}%** "
                         f"depuis plus de 5 min (seuil : {mem_thresh:.0f}%).")
                db.insert_event(rid, "warning", "system", title, desc)
                _notify(webhooks, "warning", title, desc,
                        [{"name": "Mémoire", "value": f"{mem_usage:.0f}%",  "inline": True},
                         {"name": "Seuil",   "value": f"{mem_thresh:.0f}%", "inline": True}],
                        rname)
        else:
            _high_mem_since.pop(rid, None)

    # 7. Détection conflits IP (deux MACs différents pour la même IP)
    try:
        arp_entries = db.get_arp_history(rid, limit=1000)
        ip_to_macs: dict = {}
        for entry in arp_entries:
            ip  = entry.get("ip", "")
            mac = entry.get("mac", "")
            if ip and mac:
                ip_to_macs.setdefault(ip, set()).add(mac)
        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                key = f"ip_conflict_{rid}_{ip}"
                if _cooldown_ok(key):
                    macs_str = ", ".join(sorted(macs))
                    title = f"Conflit IP détecté : {ip}"
                    desc  = (f"🔀 L'IP **{ip}** est associée à plusieurs MACs sur **{rname}** : "
                             f"{macs_str}")
                    db.insert_event(rid, "warning", "system", title, desc)
                    _notify(webhooks, "warning", title, desc,
                            [{"name": "IP",   "value": ip,       "inline": True},
                             {"name": "MACs", "value": macs_str, "inline": True}],
                            rname)
    except Exception as _e:
        log.debug("[%s] IP conflict check error: %s", rname, _e)

    # 8. WAN failover (changement d'interface WAN active)
    try:
        wan_keywords = ["wan", "dialer", "pppoe", "cellular", "wwan",
                        "ge0/0/8", "ge0/0/9", "gigabitethernet0/0/8", "gigabitethernet0/0/9"]
        cur_active_wan = set()
        for iface in ifaces:
            name_lc = (iface.get("if_name") or "").lower()
            if iface.get("if_status") == 1 and any(k in name_lc for k in wan_keywords):
                cur_active_wan.add(iface.get("if_name", ""))
        prev_wan = _prev_active_wan.get(rid)
        if prev_wan is not None and prev_wan != cur_active_wan:
            lost = prev_wan - cur_active_wan
            gained = cur_active_wan - prev_wan
            if lost or gained:
                key = f"wan_failover_{rid}"
                if _cooldown_ok(key):
                    parts = []
                    if lost:
                        parts.append(f"perdu : {', '.join(sorted(lost))}")
                    if gained:
                        parts.append(f"basculé vers : {', '.join(sorted(gained))}")
                    title = f"Basculement WAN détecté — {rname}"
                    desc  = f"🔄 Changement WAN sur **{rname}** : {' / '.join(parts)}."
                    db.insert_event(rid, "warning", "interface", title, desc)
                    _notify(webhooks, "warning", title, desc,
                            [{"name": "Perdu",    "value": ", ".join(sorted(lost))    or "—", "inline": True},
                             {"name": "Activé",   "value": ", ".join(sorted(gained))  or "—", "inline": True}],
                            rname)
        _prev_active_wan[rid] = cur_active_wan
    except Exception as _e:
        log.debug("[%s] WAN failover check error: %s", rname, _e)


# ─── BGP / OSPF state-change alerts ──────────────────────────────────────────

def _check_bgp_ospf(router: dict, webhooks: list) -> None:
    rid   = router["id"]
    rname = router["name"]

    # BGP
    try:
        bgp_peers = collect_bgp_neighbors(router)
        for peer in bgp_peers:
            key      = (rid, peer["peer_ip"])
            prev_sid = _prev_bgp_states.get(key)
            cur_sid  = peer["state_id"]
            if prev_sid is not None and prev_sid != cur_sid:
                was_up  = prev_sid == 6
                now_up  = cur_sid  == 6
                level   = "info" if now_up else "warning"
                icon    = "🟢" if now_up else "🟡"
                title   = f"BGP {peer['peer_ip']} : {peer['state']}"
                desc    = (f"{icon} Voisin BGP **{peer['peer_ip']}** sur **{rname}** "
                           f"est passé à l'état **{peer['state']}**.")
                db.insert_event(rid, level, "system", title, desc)
                if _cooldown_ok(f"bgp_{rid}_{peer['peer_ip']}"):
                    _notify(webhooks, level, title, desc,
                            [{"name": "Voisin", "value": peer["peer_ip"], "inline": True},
                             {"name": "État",   "value": peer["state"],   "inline": True}],
                            rname)
            _prev_bgp_states[key] = cur_sid
    except Exception as _e:
        log.debug("[%s] BGP check error: %s", rname, _e)

    # OSPF
    try:
        ospf_nbrs = collect_ospf_neighbors(router)
        for nbr in ospf_nbrs:
            key      = (rid, nbr["nbr_ip"])
            prev_sid = _prev_ospf_states.get(key)
            cur_sid  = nbr["state_id"]
            if prev_sid is not None and prev_sid != cur_sid:
                now_full = cur_sid == 8
                level    = "info" if now_full else "warning"
                icon     = "🟢" if now_full else "🟡"
                title    = f"OSPF {nbr['nbr_ip']} : {nbr['state']}"
                desc     = (f"{icon} Voisin OSPF **{nbr['nbr_ip']}** sur **{rname}** "
                            f"est passé à l'état **{nbr['state']}**.")
                db.insert_event(rid, level, "system", title, desc)
                if _cooldown_ok(f"ospf_{rid}_{nbr['nbr_ip']}"):
                    _notify(webhooks, level, title, desc,
                            [{"name": "Voisin", "value": nbr["nbr_ip"], "inline": True},
                             {"name": "État",   "value": nbr["state"],  "inline": True}],
                            rname)
            _prev_ospf_states[key] = cur_sid
    except Exception as _e:
        log.debug("[%s] OSPF check error: %s", rname, _e)


# ─── Table de routage ────────────────────────────────────────────────────────

_ROUTE_TYPES = {1: "other", 2: "invalid", 3: "direct", 4: "indirect"}


def _ip_str(val) -> str:
    """Convertit une valeur pysnmp (IpAddress/OctetString) en chaîne IP dotted."""
    # Méthode 1 : bytes → 4 octets
    try:
        raw = bytes(val)
        if len(raw) == 4:
            return ".".join(str(b) for b in raw)
    except Exception:
        pass
    # Méthode 2 : prettyPrint (retourne la notation dotted sur pysnmplib)
    try:
        pp = val.prettyPrint()
        if pp and "." in pp:
            return pp
    except Exception:
        pass
    return str(val)


def _ip_suffix(oid_str: str, base_oid: str) -> str | None:
    """Extrait le suffixe IP (A.B.C.D) depuis un OID de table de routage."""
    suffix = oid_str[len(base_oid):].lstrip(".")
    parts  = suffix.split(".")
    if len(parts) < 4:
        return None
    return ".".join(parts[-4:])


BGP_STATES = {1:"idle",2:"connect",3:"active",4:"opensent",5:"openconfirm",6:"established"}
OSPF_STATES = {1:"down",2:"attempt",3:"init",4:"twoway",5:"exstart",6:"exchange",7:"loading",8:"full"}


def collect_bgp_neighbors(router: dict) -> list:
    """Lit la bgpPeerTable RFC 1657. Retourne [] si BGP non configuré."""
    peers: dict = {}
    columns = [
        (config.OID_BGP_PEER_STATE,   "state",    _int),
        (config.OID_BGP_PEER_UPTIME,  "uptime",   _int),
        (config.OID_BGP_PEER_IN_UPD,  "in_upd",   _int),
        (config.OID_BGP_PEER_OUT_UPD, "out_upd",  _int),
    ]
    try:
        for base_oid, field, converter in columns:
            for oid_str, val in snmp_walk(router, base_oid):
                suffix = oid_str[len(base_oid):].lstrip(".")
                parts  = suffix.split(".")
                if len(parts) < 4:
                    continue
                peer_ip = ".".join(parts[-4:])
                entry = peers.setdefault(peer_ip, {"peer_ip": peer_ip})
                try:
                    entry[field] = converter(val)
                except Exception:
                    pass
    except Exception:
        return []
    return [
        {
            "peer_ip":  k,
            "state":    BGP_STATES.get(v.get("state"), "unknown"),
            "state_id": v.get("state", 0),
            "uptime":   v.get("uptime"),
            "in_upd":   v.get("in_upd", 0),
            "out_upd":  v.get("out_upd", 0),
        }
        for k, v in peers.items()
    ]


def collect_ospf_neighbors(router: dict) -> list:
    """Lit ospfNbrTable RFC 1850. Retourne [] si OSPF non configuré."""
    nbrs: dict = {}
    columns = [
        (config.OID_OSPF_NBR_IPADDR, "nbr_ip",  _ip_str),
        (config.OID_OSPF_NBR_RTRID,  "rtr_id",  _ip_str),
        (config.OID_OSPF_NBR_STATE,  "state",   _int),
        (config.OID_OSPF_NBR_EVENTS, "events",  _int),
    ]
    try:
        for base_oid, field, converter in columns:
            for oid_str, val in snmp_walk(router, base_oid):
                suffix = oid_str[len(base_oid):].lstrip(".")
                # Key = first 4 octets (nbr IP) + last octet (interface idx)
                parts = suffix.split(".")
                if len(parts) < 5:
                    continue
                key = ".".join(parts[:5])
                entry = nbrs.setdefault(key, {})
                try:
                    entry[field] = converter(val)
                except Exception:
                    pass
    except Exception:
        return []
    return [
        {
            "nbr_ip":  v.get("nbr_ip", k),
            "rtr_id":  v.get("rtr_id", ""),
            "state":   OSPF_STATES.get(v.get("state"), "unknown"),
            "state_id": v.get("state", 0),
            "events":  v.get("events", 0),
        }
        for k, v in nbrs.items()
    ]


def collect_dhcp_leases(router: dict) -> list:
    """Lit hwDhcpServerStatClientLeaseTable Huawei. Retourne [] si DHCP server inactif."""
    leases: dict = {}
    try:
        for oid_str, val in snmp_walk(router, config.OID_HW_DHCP_LEASE):
            suffix = oid_str[len(config.OID_HW_DHCP_LEASE):].lstrip(".")
            parts  = suffix.split(".")
            if len(parts) < 2:
                continue
            col = parts[0]
            # Index = remaining parts (can be IP or MAC-based)
            idx = ".".join(parts[1:])
            entry = leases.setdefault(idx, {})
            if col == "1":
                # MAC: 6 octets in OID suffix
                try:
                    mac_parts = [int(x) for x in parts[1:7]]
                    if len(mac_parts) == 6:
                        entry["mac"] = ":".join(f"{b:02X}" for b in mac_parts)
                except Exception:
                    entry["mac"] = str(val)
            elif col == "2":
                entry["ip"]  = _ip_str(val)
            elif col == "3":
                entry["type"] = {1: "dynamic", 2: "static", 3: "auto"}.get(_int(val), "?")
            elif col == "5":
                entry["ttl"] = _int(val)
            elif col == "9":
                entry["vrf"] = str(val).strip() or "default"
    except Exception:
        return []
    return [
        {
            "mac":  v.get("mac", ""),
            "ip":   v.get("ip", ""),
            "type": v.get("type", "?"),
            "ttl":  v.get("ttl"),
            "vrf":  v.get("vrf", "default"),
        }
        for v in leases.values()
        if v.get("ip")
    ]


def collect_dhcp_pool_stats(router: dict) -> list:
    """Retourne les stats d'utilisation des pools DHCP Huawei.
    [{pool_name, total, used, idle, pct_used}]"""
    pools: dict = {}
    try:
        for oid_str, val in snmp_walk(router, config.OID_HW_DHCP_POOL):
            suffix = oid_str[len(config.OID_HW_DHCP_POOL):].lstrip(".")
            parts  = suffix.split(".")
            if len(parts) < 2:
                continue
            col = parts[0]
            idx = ".".join(parts[1:])
            entry = pools.setdefault(idx, {})
            if   col == "3": entry["pool_name"] = str(val).strip()
            elif col == "4": entry["total"]     = _int(val)
            elif col == "5": entry["used"]      = _int(val)
            elif col == "6": entry["idle"]      = _int(val)
    except Exception:
        return []
    result = []
    for v in pools.values():
        total = v.get("total") or 0
        used  = v.get("used")  or 0
        result.append({
            "pool_name": v.get("pool_name", "?"),
            "total":     total,
            "used":      used,
            "idle":      v.get("idle"),
            "pct_used":  round(used / total * 100, 1) if total > 0 else None,
        })
    return result


def collect_routing_table(router: dict) -> list:
    """Retourne la table de routage IP via ipRouteTable (RFC 1213).
    Utilise le suffixe IP de l'OID comme clé, et prettyPrint/bytes pour décoder les IpAddress.
    """
    routes: dict[str, dict] = {}

    columns = [
        (config.OID_ROUTE_DEST,    "dest",     _ip_str),
        (config.OID_ROUTE_MASK,    "mask",     _ip_str),
        (config.OID_ROUTE_NEXTHOP, "nexthop",  _ip_str),
        (config.OID_ROUTE_TYPE,    "type",     _int),
        (config.OID_ROUTE_METRIC,  "metric",   _int),
        (config.OID_ROUTE_IFINDEX, "if_index", _int),
    ]

    for base_oid, field, converter in columns:
        for oid_str, val in snmp_walk(router, base_oid):
            key = _ip_suffix(oid_str, base_oid)
            if key is None:
                continue
            if key not in routes:
                routes[key] = {}
            try:
                routes[key][field] = converter(val)
            except Exception:
                routes[key][field] = str(val)

    result = []
    for ip_key, route in routes.items():
        rtype = route.get("type")
        if rtype == 2:   # invalid — skip
            continue
        dest = route.get("dest") or ip_key
        result.append({
            "dest":     dest,
            "mask":     route.get("mask", "0.0.0.0"),
            "nexthop":  route.get("nexthop", "0.0.0.0"),
            "type":     _ROUTE_TYPES.get(rtype, str(rtype) if rtype else "?"),
            "metric":   route.get("metric"),
            "if_index": route.get("if_index"),
        })

    return sorted(result, key=lambda r: tuple(int(x) for x in r["dest"].split("."))
                  if r["dest"].count(".") == 3 else (0, 0, 0, 0))


# ─── LTE / Cellular ───────────────────────────────────────────────────────────

def collect_lte(router: dict) -> dict | None:
    """Collecte les métriques LTE/4G/5G via Huawei hwCellularMIB.
    Retourne None si le routeur n'a pas d'interface cellulaire."""
    try:
        rows = snmp_walk(router, config.OID_LTE_BASE)
        if not rows:
            return None

        def _first(oid_base):
            vals = [v for _, v in snmp_walk(router, oid_base)]
            return vals[0] if vals else None

        rssi        = _int(_first(config.OID_LTE_RSSI))
        rsrp        = _int(_first(config.OID_LTE_RSRP))
        rsrq        = _int(_first(config.OID_LTE_RSRQ))
        sinr        = _int(_first(config.OID_LTE_SINR))
        operator    = str(_first(config.OID_LTE_OPERATOR) or "")
        access_mode = str(_first(config.OID_LTE_ACCESS_MODE) or "")
        sim_status  = _int(_first(config.OID_LTE_SIM_STATUS))

        if rssi is None and rsrp is None:
            return None

        return {
            "rssi":        rssi,        # dBm  ex: -75
            "rsrp":        rsrp,        # dBm  ex: -95
            "rsrq":        rsrq,        # dB   ex: -10
            "sinr":        sinr,        # dB   ex: 15
            "operator":    operator,    # ex: "Orange"
            "access_mode": access_mode, # ex: "LTE", "NR" (5G)
            "sim_status":  sim_status,  # 1=présente/active
        }
    except Exception as e:
        log.debug("[%s] collect_lte: %s", router["name"], e)
        return None


# ─── WiFi Radio ───────────────────────────────────────────────────────────────

def collect_wifi_radio(router: dict) -> list:
    """Collecte les infos par radio WiFi (canal, puissance TX).
    Retourne une liste [{radio_index, channel, tx_power_dbm, mode}]."""
    try:
        channels = _walk_indexed(router, config.OID_WLAN_RADIO_CHAN)
        powers   = _walk_indexed(router, config.OID_WLAN_RADIO_POWER)
        modes    = _walk_indexed(router, config.OID_WLAN_RADIO_MODE)

        if not channels:
            return []

        return [
            {
                "radio_index":   idx,
                "channel":       _int(channels.get(idx)),
                "tx_power_dbm":  _int(powers.get(idx)),
                "mode":          str(modes.get(idx, "")),  # ex: "11bgn", "11ac"
            }
            for idx in sorted(channels.keys())
        ]
    except Exception as e:
        log.debug("[%s] collect_wifi_radio: %s", router["name"], e)
        return []


# ─── Cycle complet ────────────────────────────────────────────────────────────

def poll(router: dict) -> None:
    rid = router["id"]
    log.info("[%s] Collecte SNMP → %s", router["name"], router["ip"])
    try:
        sys_data = collect_system(router)
        db.insert_system(rid, sys_data)

        ifaces = collect_interfaces(router)
        db.insert_interfaces(rid, ifaces)

        bps = compute_bps(rid, ifaces)
        db.insert_bps(rid, bps)

        check_events(router, sys_data, ifaces, bps)

        # BGP / OSPF state changes (best-effort)
        try:
            webhooks = db.get_discord_webhooks(enabled_only=True)
            _check_bgp_ospf(router, webhooks)
        except Exception as _e:
            log.debug("[%s] BGP/OSPF check error: %s", router["name"], _e)

        # LTE / Cellular (best-effort)
        try:
            lte = collect_lte(router)
            if lte:
                db.upsert_lte(rid, lte)
        except Exception as _e:
            log.debug("[%s] LTE collect error: %s", router["name"], _e)

        # WiFi radio (best-effort)
        try:
            radios = collect_wifi_radio(router)
            if radios:
                db.upsert_wifi_radio(rid, radios)
        except Exception as _e:
            log.debug("[%s] WiFi radio collect error: %s", router["name"], _e)

        # WiFi client history (best-effort)
        try:
            wifi_clients = collect_wifi_clients(router)
            if wifi_clients:
                db.insert_wifi_client_history(rid, wifi_clients)
        except Exception as _e:
            log.debug("[%s] WiFi client history error: %s", router["name"], _e)

        # ARP history + nouveau MAC (best-effort)
        try:
            clients = collect_clients(router)
            if clients:
                db.upsert_arp(rid, clients)
            # Nouveaux MACs non-connus
            new_macs = db.get_unalerted_new_macs(rid)
            if new_macs:
                wh_mac = db.get_discord_webhooks(enabled_only=True)
                for entry in new_macs:
                    title_mac = f"Nouveau client détecté : {entry['mac']}"
                    desc_mac  = (f"🔍 Nouveau MAC **{entry['mac']}** (IP : {entry['ip']}) "
                                 f"détecté sur **{router['name']}**.")
                    db.insert_event(rid, "info", "system", title_mac, desc_mac)
                    if _cooldown_ok(f"newmac_{rid}_{entry['mac']}"):
                        _notify(wh_mac, "info", title_mac, desc_mac,
                                [{"name": "MAC", "value": entry["mac"], "inline": True},
                                 {"name": "IP",  "value": entry["ip"],  "inline": True}],
                                router["name"], router_id=rid)
                    db.mark_mac_alerted(rid, entry["mac"])
        except Exception as _e:
            log.debug("[%s] ARP/MAC check error: %s", router["name"], _e)

        # WAN SLA — enregistrer l'état courant de chaque interface WAN
        try:
            wan_keywords = ["wan", "dialer", "pppoe", "cellular", "wwan",
                            "ge0/0/8", "ge0/0/9", "gigabitethernet0/0/8", "gigabitethernet0/0/9"]
            for iface in ifaces:
                name_lc = (iface.get("if_name") or "").lower()
                if any(k in name_lc for k in wan_keywords):
                    db.insert_wan_sla(rid, iface["if_index"],
                                      iface.get("if_name", ""),
                                      iface.get("if_status") == 1)
        except Exception as _e:
            log.debug("[%s] WAN SLA error: %s", router["name"], _e)

        # Totaux bande passante (best-effort)
        try:
            poll_interval = router.get("poll_interval", 60)
            for brow in bps:
                if brow.get("in_bps") is not None and brow.get("out_bps") is not None:
                    in_delta  = int(brow["in_bps"]  * poll_interval / 8)
                    out_delta = int(brow["out_bps"] * poll_interval / 8)
                    db.accumulate_bandwidth(rid, brow["if_index"],
                                            brow.get("if_name", ""),
                                            in_delta, out_delta)
        except Exception as _e:
            log.debug("[%s] Bandwidth totals error: %s", router["name"], _e)

        # OIDs personnalisés (best-effort)
        try:
            custom_polls = db.get_custom_oid_polls(rid, enabled_only=True)
            for cp in custom_polls:
                val = snmp_get(router, cp["oid"])
                if val is not None:
                    txt = str(val)
                    try:
                        num = float(val)
                    except Exception:
                        num = None
                    db.insert_custom_oid_value(cp["id"], txt, num)
        except Exception as _e:
            log.debug("[%s] Custom OID poll error: %s", router["name"], _e)

        # DHCP pool exhaustion check (best-effort)
        try:
            dhcp_warn_pct = float(db.get_settings().get("alert_dhcp_warn_pct", 80))
            dhcp_pools    = collect_dhcp_pool_stats(router)
            wh_dhcp       = db.get_discord_webhooks(enabled_only=True)
            for pool in dhcp_pools:
                pct = pool.get("pct_used")
                if pct is not None and pct >= dhcp_warn_pct:
                    key = f"dhcp_{rid}_{pool['pool_name']}"
                    if _cooldown_ok(key):
                        title = f"Pool DHCP saturé : {pool['pool_name']} ({pct:.0f}%)"
                        desc  = (f"📦 Le pool DHCP **{pool['pool_name']}** sur **{router['name']}** "
                                 f"est utilisé à **{pct:.0f}%** ({pool['used']}/{pool['total']} adresses).")
                        db.insert_event(rid, "warning", "system", title, desc)
                        _notify(wh_dhcp, "warning", title, desc,
                                [{"name": "Pool",       "value": pool["pool_name"],     "inline": True},
                                 {"name": "Utilisé",    "value": f"{pool['used']}/{pool['total']}", "inline": True},
                                 {"name": "Saturation", "value": f"{pct:.0f}%",         "inline": True}],
                                router["name"])
        except Exception as _e:
            log.debug("[%s] DHCP pool check error: %s", router["name"], _e)

        db.purge_old(rid, router.get("retention_days", 30))
        db.purge_events(days=router.get("retention_days", 30))
        log.info("[%s] OK — CPU:%s%% MEM:%s%% ifaces:%d",
                 router["name"], sys_data.get("cpu_usage"),
                 sys_data.get("mem_usage"), len(ifaces))
    except Exception as e:
        log.error("[%s] Erreur collecte: %s", router["name"], e)
