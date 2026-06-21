import json
import logging
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)


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


def notify_new_ports(db, target_id: int, host: str, new_ports: list[dict]) -> None:
    from . import crud
    webhook = crud.get_setting(db, "slack_webhook_url")
    if not webhook:
        return
    if crud.get_setting(db, "slack_notify_new_ports") == "false":
        return

    port_list = ", ".join(f"`{p['port']}/{p['protocol']}`" for p in new_ports[:15])
    extra = f" (+{len(new_ports) - 15} ещё)" if len(new_ports) > 15 else ""
    msg = (
        f":rotating_light: *Port Monitor* — новые открытые порты на `{host}`\n"
        f"Порты: {port_list}{extra}"
    )
    try:
        send_slack_message(webhook, msg)
    except Exception as e:
        logger.warning("Slack notification failed: %s", e)
