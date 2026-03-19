"""
Récepteur SNMP Trap UDP — HuwaControl.
Écoute les traps SNMPv1/v2c sur UDP (port configurable, défaut 1162).
Décode les varbinds, crée des événements dans la base de données.
"""
import logging
import socket
import struct
import threading
import time

import database as db

log = logging.getLogger("snmp_trap")

# OIDs courants pour le décodage
OID_TRAP_OID   = "1.3.6.1.6.3.1.1.4.1.0"
OID_LINK_DOWN  = "1.3.6.1.6.3.1.1.5.3"
OID_LINK_UP    = "1.3.6.1.6.3.1.1.5.4"
OID_SYSUPTIME  = "1.3.6.1.2.1.1.3.0"

# Type ASN.1 / BER tags
_TAG_INT       = 0x02
_TAG_OCTET_STR = 0x04
_TAG_NULL      = 0x05
_TAG_OID       = 0x06
_TAG_SEQ       = 0x30
_TAG_IPADDR    = 0x40
_TAG_COUNTER   = 0x41
_TAG_GAUGE     = 0x42
_TAG_TIMETICKS = 0x43
_TAG_OPAQUE    = 0x44
_TAG_COUNTER64 = 0x46
_TAG_GETRESP   = 0xA2
_TAG_TRAP_V1   = 0xA4
_TAG_TRAP_V2   = 0xA7


# ─── BER / ASN.1 minimal decoder ─────────────────────────────────────────────

def _read_length(data: bytes, offset: int):
    """Read BER length encoding. Returns (length, new_offset)."""
    b = data[offset]; offset += 1
    if b & 0x80 == 0:
        return b, offset
    n = b & 0x7F
    length = int.from_bytes(data[offset:offset+n], 'big')
    return length, offset + n


def _decode_oid(data: bytes) -> str:
    """Decode BER-encoded OID bytes to dotted string."""
    if not data:
        return ""
    first = data[0]
    parts = [str(first // 40), str(first % 40)]
    val = 0
    for b in data[1:]:
        if b & 0x80:
            val = (val << 7) | (b & 0x7F)
        else:
            val = (val << 7) | b
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def _decode_value(tag: int, data: bytes):
    """Return a Python value for a BER-encoded SNMP varbind value."""
    if tag == _TAG_INT:
        return int.from_bytes(data, 'big', signed=True)
    if tag == _TAG_OCTET_STR:
        try:
            return data.decode('utf-8', errors='replace')
        except Exception:
            return data.hex()
    if tag == _TAG_NULL:
        return None
    if tag == _TAG_OID:
        return _decode_oid(data)
    if tag == _TAG_IPADDR and len(data) == 4:
        return ".".join(str(b) for b in data)
    if tag in (_TAG_COUNTER, _TAG_GAUGE, _TAG_TIMETICKS,
               _TAG_COUNTER64, _TAG_OPAQUE):
        return int.from_bytes(data, 'big')
    return data.hex()


def _parse_tlv(data: bytes, offset: int = 0):
    """Parse one TLV at offset. Returns (tag, value_bytes, next_offset)."""
    if offset >= len(data):
        raise ValueError("Truncated TLV")
    tag = data[offset]; offset += 1
    length, offset = _read_length(data, offset)
    value = data[offset:offset+length]
    return tag, value, offset + length


def _parse_varbind_list(data: bytes) -> list[tuple[str, object]]:
    """Parse a SEQ-OF varbind sequence. Returns [(oid_str, value), ...]."""
    result = []
    off = 0
    while off < len(data):
        tag, vbytes, off = _parse_tlv(data, off)
        if tag != _TAG_SEQ:
            continue
        # Each varbind: SEQUENCE { OID, value }
        inner_off = 0
        try:
            t1, oid_bytes, inner_off = _parse_tlv(vbytes, inner_off)
            if t1 != _TAG_OID:
                continue
            oid_str = _decode_oid(oid_bytes)
            t2, val_bytes, _ = _parse_tlv(vbytes, inner_off)
            value = _decode_value(t2, val_bytes)
            result.append((oid_str, value))
        except Exception:
            continue
    return result


def parse_trap(data: bytes, source_ip: str) -> dict | None:
    """
    Parse SNMPv1 or SNMPv2c trap PDU.
    Returns a dict with: version, community, trap_oid, source_ip, uptime, varbinds.
    """
    try:
        off = 0
        # Top-level SEQUENCE
        tag, msg_bytes, off = _parse_tlv(data, off)
        if tag != _TAG_SEQ:
            return None
        off = 0
        data = msg_bytes

        # Version
        t, v, off = _parse_tlv(data, off)
        version = int.from_bytes(v, 'big') if t == _TAG_INT else 0

        # Community
        t, v, off = _parse_tlv(data, off)
        community = v.decode('ascii', errors='replace') if t == _TAG_OCTET_STR else ""

        # PDU
        t, pdu_bytes, off = _parse_tlv(data, off)

        trap_oid = ""
        uptime   = 0
        varbinds = []

        if t == _TAG_TRAP_V1:
            # SNMPv1 Trap: enterprise OID, agent-addr, generic-trap, specific-trap, time-stamp, varbinds
            p = 0
            t2, enterprise_bytes, p = _parse_tlv(pdu_bytes, p)
            enterprise = _decode_oid(enterprise_bytes) if t2 == _TAG_OID else ""
            t2, agent_bytes, p = _parse_tlv(pdu_bytes, p)
            t2, generic_bytes, p = _parse_tlv(pdu_bytes, p)
            generic = int.from_bytes(generic_bytes, 'big') if t2 == _TAG_INT else 0
            t2, specific_bytes, p = _parse_tlv(pdu_bytes, p)
            specific = int.from_bytes(specific_bytes, 'big') if t2 == _TAG_INT else 0
            t2, ts_bytes, p = _parse_tlv(pdu_bytes, p)
            uptime = int.from_bytes(ts_bytes, 'big') if t2 == _TAG_TIMETICKS else 0
            # Varbind list
            t2, vb_bytes, p = _parse_tlv(pdu_bytes, p)
            if t2 == _TAG_SEQ:
                varbinds = _parse_varbind_list(vb_bytes)
            # Derive trapOID from generic type
            _GENERIC_OIDS = {
                0: "1.3.6.1.6.3.1.1.5.1",  # coldStart
                1: "1.3.6.1.6.3.1.1.5.2",  # warmStart
                2: OID_LINK_DOWN,
                3: OID_LINK_UP,
                4: "1.3.6.1.6.3.1.1.5.5",  # authenticationFailure
                5: "1.3.6.1.6.3.1.1.5.6",  # egpNeighborLoss
                6: f"{enterprise}.0.{specific}",  # enterpriseSpecific
            }
            trap_oid = _GENERIC_OIDS.get(generic, enterprise)

        elif t == _TAG_TRAP_V2:
            # SNMPv2c Trap / Inform: request-id, error-status, error-index, varbinds
            p = 0
            _t, _v, p = _parse_tlv(pdu_bytes, p)  # request-id
            _t, _v, p = _parse_tlv(pdu_bytes, p)  # error-status
            _t, _v, p = _parse_tlv(pdu_bytes, p)  # error-index
            t2, vb_bytes, p = _parse_tlv(pdu_bytes, p)
            if t2 == _TAG_SEQ:
                varbinds = _parse_varbind_list(vb_bytes)
            # Extract sysUpTime and snmpTrapOID from varbinds
            for oid, val in varbinds:
                if oid == OID_SYSUPTIME:
                    uptime = val or 0
                elif oid == OID_TRAP_OID:
                    trap_oid = str(val)
        else:
            return None

        return {
            "version":    version,
            "community":  community,
            "source_ip":  source_ip,
            "trap_oid":   trap_oid,
            "uptime_cs":  uptime,
            "varbinds":   varbinds,
        }
    except Exception as e:
        log.debug("Trap parse error from %s: %s", source_ip, e)
        return None


def _trap_to_event(trap: dict) -> tuple[str, str, str]:
    """Convert a parsed trap to (level, title, message) for insert_event."""
    oid   = trap["trap_oid"]
    src   = trap["source_ip"]
    vbs   = dict(trap["varbinds"])

    if oid == OID_LINK_DOWN or oid.endswith(".3"):
        level = "error"
        title = "Interface DOWN (SNMP Trap)"
        iface = next((str(v) for k, v in trap["varbinds"]
                      if "ifDescr" in k or k.startswith("1.3.6.1.2.1.2.2.1.2")), "?")
        msg   = f"Interface {iface} est passée DOWN — source {src}"
    elif oid == OID_LINK_UP or oid.endswith(".4"):
        level = "success"
        title = "Interface UP (SNMP Trap)"
        iface = next((str(v) for k, v in trap["varbinds"]
                      if "ifDescr" in k or k.startswith("1.3.6.1.2.1.2.2.1.2")), "?")
        msg   = f"Interface {iface} est remontée UP — source {src}"
    elif oid.endswith(".1") or oid.endswith(".2"):
        level = "info"
        title = "Redémarrage routeur (SNMP Trap)"
        msg   = f"coldStart/warmStart reçu depuis {src}"
    elif oid.endswith(".5"):
        level = "warning"
        title = "Échec d'authentification SNMP (Trap)"
        msg   = f"authenticationFailure depuis {src}"
    else:
        level = "info"
        title = f"SNMP Trap — {oid.split('.')[-1]}"
        msg   = f"OID: {oid} — source: {src}"
        if vbs:
            pairs = ", ".join(f"{k}={v}" for k, v in list(vbs.items())[:4])
            msg  += f"\n{pairs}"

    return level, title, msg


def _find_router_by_ip(source_ip: str) -> int | None:
    """Return router_id matching source_ip, or None."""
    try:
        routers = db.get_enabled_routers()
        for r in routers:
            if r.get("host") == source_ip:
                return r["id"]
        return routers[0]["id"] if routers else None
    except Exception:
        return None


class SnmpTrapReceiver:
    def __init__(self, host: str = "0.0.0.0", port: int = 1162):
        self.host    = host
        self.port    = port
        self._sock   = None
        self._thread = None
        self._stop   = threading.Event()

    def start(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.host, self.port))
            self._sock.settimeout(1.0)
            self._thread = threading.Thread(
                target=self._loop, daemon=True, name="snmp-trap-recv")
            self._thread.start()
            log.info("SNMP Trap receiver listening on UDP %s:%d", self.host, self.port)
        except PermissionError:
            log.warning(
                "Cannot bind UDP %d for SNMP traps (permission denied). "
                "Use port 1162 or higher, or run with CAP_NET_BIND_SERVICE.", self.port)
        except Exception as e:
            log.error("SNMP Trap receiver failed to start: %s", e)

    def stop(self):
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def _loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)
                source_ip  = addr[0]
                trap = parse_trap(data, source_ip)
                if trap is None:
                    continue
                router_id = _find_router_by_ip(source_ip)
                level, title, msg = _trap_to_event(trap)
                db.insert_event(
                    router_id=router_id,
                    level=level,
                    category="snmp_trap",
                    title=title,
                    message=msg,
                )
                log.info("SNMP Trap from %s: %s — %s", source_ip, trap["trap_oid"], title)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                log.debug("snmp_trap error: %s", e)
