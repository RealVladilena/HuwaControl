"""
Module de notifications — HuwaControl.
Envoi d'embeds via webhooks Discord, bots Telegram, et emails SMTP.
"""
import json
import logging
import smtplib
import time
import urllib.error
import urllib.request
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

log = logging.getLogger("notifications")

_COLORS = {
    "info":    0x5865F2,   # Bleu Discord
    "success": 0x57F287,   # Vert
    "warning": 0xFEE75C,   # Jaune
    "error":   0xED4245,   # Rouge
}
_ICONS = {
    "info":    "ℹ️",
    "success": "✅",
    "warning": "⚠️",
    "error":   "🚨",
}


def send_discord(url: str, level: str, title: str, description: str,
                 fields: list | None = None, router_name: str = "") -> bool:
    """Envoie un embed Discord au webhook donné. Retourne True si succès."""
    if not url:
        return False

    embed = {
        "title":       f"{_ICONS.get(level, 'ℹ️')} {title}",
        "description": description,
        "color":       _COLORS.get(level, 0x5865F2),
        "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "footer": {
            "text": f"HuwaControl • {router_name}" if router_name else "HuwaControl",
        },
    }
    if fields:
        embed["fields"] = fields

    payload = {
        "username": "HuwaControl",
        "embeds":   [embed],
    }
    try:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json",
                     "User-Agent": "HuwaControl/1.0 (Discord Webhook)"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            ok = resp.status in (200, 204)
            if not ok:
                log.warning("Webhook HTTP %d", resp.status)
            return ok
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode(errors="replace")
        except Exception:
            pass
        log.error("Discord webhook HTTP %d: %s", e.code, body)
        return False
    except Exception as e:
        log.error("Discord webhook error: %s", e)
        return False


def send_telegram(bot_token: str, chat_id: str, level: str,
                  title: str, description: str, router_name: str = "") -> bool:
    """Envoie un message Telegram via Bot API. Retourne True si succès."""
    if not bot_token or not chat_id:
        return False
    icon = _ICONS.get(level, "ℹ️")
    text = f"{icon} *{title}*\n{description}"
    if router_name:
        text += f"\n_Routeur : {router_name}_"
    payload = {
        "chat_id":    chat_id,
        "text":       text,
        "parse_mode": "Markdown",
    }
    try:
        url  = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json",
                     "User-Agent": "HuwaControl/1.0 (Telegram Bot)"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            ok = resp.status == 200
            if not ok:
                log.warning("Telegram API HTTP %d", resp.status)
            return ok
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode(errors="replace")
        except Exception:
            pass
        log.error("Telegram HTTP %d: %s", e.code, body)
        return False
    except Exception as e:
        log.error("Telegram error: %s", e)
        return False


def send_telegram_test(bot_token: str, chat_id: str, name: str) -> tuple[bool, str]:
    """Envoie un message test Telegram. Retourne (succès, erreur)."""
    if not bot_token or not chat_id:
        return False, "Token ou Chat ID manquant"
    payload = {
        "chat_id":    chat_id,
        "text":       f"✅ *Test HuwaControl*\nLe bot Telegram *{name}* est opérationnel.",
        "parse_mode": "Markdown",
    }
    try:
        url  = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json",
                     "User-Agent": "HuwaControl/1.0 (Telegram Bot)"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                return True, ""
            return False, f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode(errors="replace")
        except Exception:
            pass
        return False, f"HTTP {e.code} — {body[:120]}"
    except Exception as e:
        return False, str(e)


def send_email(smtp_host: str, smtp_port: int, smtp_user: str, smtp_pass: str,
               from_addr: str, to_addrs: list[str], level: str,
               title: str, description: str, router_name: str = "") -> bool:
    """Envoie un email via SMTP. Retourne True si succès."""
    if not smtp_host or not to_addrs:
        return False
    icon = _ICONS.get(level, "ℹ️")
    subject = f"[HuwaControl] {icon} {title}"
    body_text = f"{title}\n\n{description}"
    if router_name:
        body_text += f"\n\nRouteur : {router_name}"
    body_html = f"""<html><body style="font-family:sans-serif;background:#1a1a1a;color:#e8e8e8;padding:24px">
<h2 style="color:#5865F2">{icon} {title}</h2>
<p>{description}</p>
{"<p><em>Routeur : " + router_name + "</em></p>" if router_name else ""}
<hr style="border-color:#2d2d2d">
<small style="color:#7a7a7a">HuwaControl — Monitoring Huawei</small>
</body></html>"""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_addr or smtp_user
    msg["To"]      = ", ".join(to_addrs)
    msg.attach(MIMEText(body_text, "plain", "utf-8"))
    msg.attach(MIMEText(body_html, "html",  "utf-8"))
    try:
        with smtplib.SMTP(smtp_host, int(smtp_port), timeout=10) as s:
            s.ehlo()
            if s.has_extn("STARTTLS"):
                s.starttls()
                s.ehlo()
            if smtp_user and smtp_pass:
                s.login(smtp_user, smtp_pass)
            s.sendmail(msg["From"], to_addrs, msg.as_string())
        return True
    except Exception as e:
        log.error("Email error: %s", e)
        return False


def send_email_test(smtp_host: str, smtp_port: int, smtp_user: str, smtp_pass: str,
                    from_addr: str, to_addrs: list[str]) -> tuple[bool, str]:
    """Envoie un email test. Retourne (succès, erreur)."""
    try:
        ok = send_email(smtp_host, smtp_port, smtp_user, smtp_pass,
                        from_addr, to_addrs, "success",
                        "Test HuwaControl",
                        "La configuration SMTP est correcte et opérationnelle.")
        return ok, "" if ok else "Échec d'envoi (pas d'erreur)"
    except Exception as e:
        return False, str(e)


def send_discord_test(url: str, name: str) -> tuple[bool, str]:
    """Envoie un message test et retourne (succès, message_erreur)."""
    if not url:
        return False, "URL vide"
    embed = {
        "title":       "✅ Test HuwaControl",
        "description": "Ce webhook Discord est correctement configuré et opérationnel.",
        "color":       0x57F287,
        "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "footer":      {"text": "HuwaControl"},
        "fields": [
            {"name": "Webhook", "value": name,           "inline": True},
            {"name": "Statut",  "value": "Connexion OK", "inline": True},
        ],
    }
    payload = {"username": "HuwaControl", "embeds": [embed]}
    try:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json",
                     "User-Agent": "HuwaControl/1.0 (Discord Webhook)"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status in (200, 204):
                return True, ""
            return False, f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode(errors="replace")
        except Exception:
            pass
        log.error("Discord test HTTP %d: %s", e.code, body)
        return False, f"HTTP {e.code} — {body[:120]}"
    except Exception as e:
        log.error("Discord test error: %s", e)
        return False, str(e)
