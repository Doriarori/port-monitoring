import json
import logging
import smtplib
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


# ── Slack ─────────────────────────────────────────────────────────────────────

def send_slack_message(webhook_url: str, text: str) -> None:
    payload = json.dumps({"text": text}).encode()
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"Slack API Error: {e.code} — {body}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Slack connection error: {e.reason}")


# ── Generic webhook ───────────────────────────────────────────────────────────

def send_webhook_message(webhook_url: str, payload: dict) -> None:
    data = json.dumps(payload, default=str).encode()
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"Webhook error: {e.code} — {body}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Webhook connection error: {e.reason}")


# ── Email (SMTP) ──────────────────────────────────────────────────────────────

def send_email(
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_pass: str,
    to_addr: str,
    subject: str,
    body: str,
    use_tls: bool = True,
) -> None:
    msg = MIMEMultipart()
    msg["From"] = smtp_user
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.ehlo()
            if use_tls:
                server.starttls()
                server.ehlo()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)
    except smtplib.SMTPException as e:
        raise RuntimeError(f"SMTP error: {e}")
    except OSError as e:
        raise RuntimeError(f"SMTP connection error: {e}")


# ── Unified notifications ─────────────────────────────────────────────────────

def notify_new_ports(db, target_id: int, host: str, new_ports: list[dict]) -> None:
    from . import crud

    ts = datetime.now(timezone.utc).isoformat()
    port_list_str = ", ".join(f"`{p['port']}/{p['protocol']}`" for p in new_ports[:15])
    extra = f" (+{len(new_ports) - 15} more)" if len(new_ports) > 15 else ""

    # Slack
    webhook = crud.get_setting(db, "slack_webhook_url")
    if webhook and crud.get_setting(db, "slack_notify_new_ports") != "false":
        msg = (
            f":rotating_light: *Port Monitor* — new open ports on `{host}`\n"
            f"Ports: {port_list_str}{extra}"
        )
        try:
            send_slack_message(webhook, msg)
        except Exception as e:
            logger.warning("Slack notification failed: %s", e)

    # Generic webhook
    wh_url = crud.get_setting(db, "webhook_url")
    if wh_url and crud.get_setting(db, "webhook_notify_new_ports") != "false":
        payload = {
            "event": "new_open_ports",
            "host": host,
            "ports": [
                {"port": p["port"], "protocol": p["protocol"], "service": p.get("service")}
                for p in new_ports
            ],
            "timestamp": ts,
        }
        try:
            send_webhook_message(wh_url, payload)
        except Exception as e:
            logger.warning("Webhook notification failed: %s", e)

    # Email
    smtp_host = crud.get_setting(db, "smtp_host")
    smtp_to   = crud.get_setting(db, "smtp_to")
    if smtp_host and smtp_to and crud.get_setting(db, "smtp_notify_new_ports") != "false":
        port_txt = "\n".join(
            f"  - {p['port']}/{p['protocol']}" + (f" ({p.get('service')})" if p.get("service") else "")
            for p in new_ports
        )
        body = (
            f"Port Monitor detected new open ports on host: {host}\n\n"
            f"New ports:\n{port_txt}\n\n"
            f"Detected at: {ts}\n"
        )
        try:
            send_email(
                smtp_host=smtp_host,
                smtp_port=int(crud.get_setting(db, "smtp_port") or "587"),
                smtp_user=crud.get_setting(db, "smtp_user") or "",
                smtp_pass=crud.get_setting(db, "smtp_pass") or "",
                to_addr=smtp_to,
                subject=f"[Port Monitor] New open ports on {host}",
                body=body,
                use_tls=crud.get_setting(db, "smtp_tls") != "false",
            )
        except Exception as e:
            logger.warning("Email notification failed: %s", e)
