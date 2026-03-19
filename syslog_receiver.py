"""
Syslog UDP receiver — écoute sur UDP 514 (ou SYSLOG_PORT) et stocke les messages
en base. Supporte RFC 3164 et une partie de RFC 5424.
"""
import logging
import re
import socket
import threading
import time
from datetime import datetime, timezone

import database as db
import notifications

log = logging.getLogger("syslog_receiver")

# Default keywords that trigger an alert notification
_DEFAULT_KEYWORDS = ["error", "critical", "down", "fail", "denied"]

# RFC 3164 priority + header: <PRI>TIMESTAMP HOSTNAME MESSAGE
_RE_RFC3164 = re.compile(
    r"^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)",
    re.DOTALL,
)
# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APPNAME PROCID MSGID ...
_RE_RFC5424 = re.compile(
    r"^<(\d{1,3})>1\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+(.*)",
    re.DOTALL,
)
# Program name embedded in message: "PROG: message" or "PROG[PID]: message"
_RE_PROG = re.compile(r"^([\w/\-\.]+)(?:\[\d+\])?: (.*)", re.DOTALL)

MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

SEVERITY_NAMES = {
    0: "EMERG", 1: "ALERT", 2: "CRIT", 3: "ERROR",
    4: "WARN",  5: "NOTICE", 6: "INFO", 7: "DEBUG",
}
FACILITY_NAMES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth",
    5: "syslog", 6: "lpr",  7: "news", 8: "uucp", 9: "cron",
    10: "authpriv", 16: "local0", 17: "local1", 18: "local2",
    19: "local3", 20: "local4", 21: "local5", 22: "local6", 23: "local7",
}


def _parse_rfc3164_ts(ts_str: str) -> int:
    """Parse 'MMM DD HH:MM:SS' → unix timestamp (current year)."""
    try:
        parts = ts_str.split()
        month = MONTHS.get(parts[0].lower(), 1)
        day   = int(parts[1])
        h, m, s = map(int, parts[2].split(":"))
        year = datetime.now().year
        dt = datetime(year, month, day, h, m, s, tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        return int(time.time())


def parse_message(raw: str, source_ip: str) -> dict | None:
    raw = raw.strip()
    if not raw.startswith("<"):
        return None

    ts = int(time.time())
    facility = 1
    severity = 6
    hostname = source_ip
    program  = ""
    message  = raw

    m5424 = _RE_RFC5424.match(raw)
    if m5424:
        pri       = int(m5424.group(1))
        facility  = pri >> 3
        severity  = pri & 0x07
        ts_str    = m5424.group(2)
        hostname  = m5424.group(3).strip("-") or source_ip
        program   = m5424.group(4).strip("-")
        message   = m5424.group(5).strip()
        try:
            ts = int(datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp())
        except Exception:
            pass
    else:
        m3164 = _RE_RFC3164.match(raw)
        if m3164:
            pri      = int(m3164.group(1))
            facility = pri >> 3
            severity = pri & 0x07
            ts       = _parse_rfc3164_ts(m3164.group(2))
            hostname = m3164.group(3).strip("-") or source_ip
            message  = m3164.group(4).strip()
        else:
            # No header — try to strip just the priority
            m_pri = re.match(r"^<(\d{1,3})>(.*)", raw, re.DOTALL)
            if m_pri:
                pri      = int(m_pri.group(1))
                facility = pri >> 3
                severity = pri & 0x07
                message  = m_pri.group(2).strip()

    # Extract program from message body
    mp = _RE_PROG.match(message)
    if mp and not program:
        program = mp.group(1)
        message = mp.group(2)

    # Strip structured data if present (RFC 5424 SD-ELEMENT)
    message = re.sub(r"^\[.*?\]\s*", "", message).strip()
    if not message:
        return None

    return {
        "ts":        ts,
        "source_ip": source_ip,
        "facility":  facility,
        "severity":  severity,
        "hostname":  hostname,
        "program":   program,
        "message":   message,
    }


class SyslogReceiver:
    def __init__(self, host: str = "0.0.0.0", port: int = 514):
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
            self._thread = threading.Thread(target=self._loop, daemon=True, name="syslog-recv")
            self._thread.start()
            log.info("Syslog receiver listening on UDP %s:%d", self.host, self.port)
        except PermissionError:
            log.warning(
                "Cannot bind UDP %d (permission denied). "
                "Use port 1514 or run with CAP_NET_BIND_SERVICE.", self.port
            )
        except Exception as e:
            log.error("Syslog receiver failed to start: %s", e)

    def stop(self):
        self._stop.set()
        if self._sock:
            self._sock.close()

    def _check_keywords(self, parsed: dict) -> None:
        """Send alert notifications if message matches configured keywords."""
        try:
            cfg = db.get_settings()
            raw_kw = cfg.get("syslog_alert_keywords", "") if cfg else ""
            keywords = [k.strip().lower() for k in raw_kw.split(",") if k.strip()]
            if not keywords:
                keywords = _DEFAULT_KEYWORDS

            msg_lower = (parsed.get("message") or "").lower()
            matched = next((kw for kw in keywords if kw in msg_lower), None)
            if not matched:
                return

            # Only notify for severity <= WARNING (0-4)
            if parsed.get("severity", 6) > 4:
                return

            title   = f"[Syslog] Alerte — {parsed.get('hostname', parsed['source_ip'])}"
            message = f"**{parsed.get('program') or 'syslog'}**: {parsed['message']}"

            webhooks = db.get_discord_webhooks(enabled_only=True)
            tg_bots  = db.get_telegram_bots(enabled_only=True)

            level = "error" if parsed.get("severity", 6) <= 3 else "warning"

            for wh in webhooks:
                notifications.send_discord(
                    wh["url"], level, title, message,
                    router_name=parsed.get("hostname", "")
                )
            for bot in tg_bots:
                notifications.send_telegram(
                    bot["bot_token"], bot["chat_id"],
                    level, title, message,
                    parsed.get("hostname", "")
                )
        except Exception as e:
            log.debug("syslog keyword alert error: %s", e)

    def _loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)
                raw = data.decode("utf-8", errors="replace")
                parsed = parse_message(raw, addr[0])
                if parsed:
                    db.insert_syslog(**parsed)
                    self._check_keywords(parsed)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                log.debug("syslog parse error: %s", e)
