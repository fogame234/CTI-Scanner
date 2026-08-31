"""
ntfy push notification integration.

Reads configuration from the database (scanner_settings table) first,
falling back to .env values. This allows ntfy to be configured
entirely from the Settings UI.
"""

import logging
from datetime import datetime, timezone

import httpx

import config

logger = logging.getLogger(__name__)

_client: httpx.AsyncClient | None = None


async def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(timeout=15)
    return _client


async def _get_ntfy_config() -> dict:
    """
    Get ntfy config. Priority:
    1. DB settings (set via Settings UI)
    2. .env values (auto-detected on first run and seeded into DB)
    
    Only one config path exists — once .env values are seeded into DB,
    the DB is authoritative. No duplicate notifications.
    """
    try:
        import db_router as db
        enabled = await db.get_setting("ntfy_enabled", "")
        url = await db.get_setting("ntfy_url", "")
        topic = await db.get_setting("ntfy_topic", "")
        token = await db.get_setting("ntfy_token", "")
        p_alert = await db.get_setting("ntfy_priority_alert", "")
        p_health = await db.get_setting("ntfy_priority_health", "")

        # If DB has values, use them
        if url:
            return {
                "enabled": enabled.lower() in ("true", "1", "yes"),
                "url": url,
                "topic": topic or "cti-alerts",
                "token": token,
                "priority_alert": int(p_alert or "4"),
                "priority_health": int(p_health or "5"),
                "source": "settings",
            }

        # DB empty — check .env
        env_url = getattr(config, "NTFY_URL", "")
        if env_url:
            return {
                "enabled": True,
                "url": env_url,
                "topic": getattr(config, "NTFY_TOPIC", "cti-alerts"),
                "token": getattr(config, "NTFY_TOKEN", ""),
                "priority_alert": int(getattr(config, "NTFY_PRIORITY_ALERT", "4")),
                "priority_health": int(getattr(config, "NTFY_PRIORITY_HEALTH", "5")),
                "source": "env",
            }

        # Nothing configured anywhere
        return {"enabled": False, "url": "", "topic": "", "token": "",
                "priority_alert": 4, "priority_health": 5, "source": "none"}

    except Exception:
        # DB not available — use .env directly
        env_url = getattr(config, "NTFY_URL", "")
        return {
            "enabled": bool(env_url),
            "url": env_url,
            "topic": getattr(config, "NTFY_TOPIC", "cti-alerts"),
            "token": getattr(config, "NTFY_TOKEN", ""),
            "priority_alert": int(getattr(config, "NTFY_PRIORITY_ALERT", "4")),
            "priority_health": int(getattr(config, "NTFY_PRIORITY_HEALTH", "5")),
            "source": "env",
        }


async def seed_ntfy_from_env():
    """
    If .env has NTFY_URL configured but the DB has no ntfy settings,
    seed the DB with the .env values. This way Docker users who
    configure via .env get their values shown in the Settings UI
    automatically, and there's only one config path going forward.
    """
    try:
        import db_router as db
        existing_url = await db.get_setting("ntfy_url", "")
        if existing_url:
            return  # DB already configured, don't overwrite

        env_url = getattr(config, "NTFY_URL", "")
        if not env_url:
            return  # Nothing in .env either

        logger.info("Seeding ntfy settings from .env into database")
        await db.set_setting("ntfy_enabled", "true")
        await db.set_setting("ntfy_url", env_url)
        await db.set_setting("ntfy_topic", getattr(config, "NTFY_TOPIC", "cti-alerts"))
        await db.set_setting("ntfy_token", getattr(config, "NTFY_TOKEN", ""))
        await db.set_setting("ntfy_priority_alert", str(getattr(config, "NTFY_PRIORITY_ALERT", "4")))
        await db.set_setting("ntfy_priority_health", str(getattr(config, "NTFY_PRIORITY_HEALTH", "5")))
    except Exception as e:
        logger.warning("Could not seed ntfy settings: %s", e)


async def _send(
    title: str,
    message: str,
    priority: int = 3,
    tags: list[str] | None = None,
    click_url: str = "",
) -> bool:
    """Send a notification to ntfy. Returns True on success."""
    cfg = await _get_ntfy_config()
    if not cfg["enabled"] or not cfg["url"] or not cfg["topic"]:
        return False

    url = f"{cfg['url'].rstrip('/')}/{cfg['topic']}"
    headers: dict[str, str] = {
        "Title": title,
        "Priority": str(priority),
    }

    if tags:
        headers["Tags"] = ",".join(tags)
    if click_url:
        headers["Click"] = click_url
    if cfg["token"]:
        headers["Authorization"] = f"Bearer {cfg['token']}"

    try:
        client = await _get_client()
        resp = await client.post(url, content=message, headers=headers)
        if resp.status_code in (200, 201):
            logger.debug("ntfy sent: %s", title)
            return True
        else:
            logger.warning("ntfy error %d: %s", resp.status_code, resp.text[:200])
            return False
    except Exception as e:
        logger.warning("ntfy send failed: %s", e)
        return False


# ══════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ══════════════════════════════════════════════════════════════════════

async def send_alert(
    keyword: str,
    channel_title: str,
    snippet: str,
    channel_id: int | None = None,
):
    """Push a keyword alert to ntfy."""
    cfg = await _get_ntfy_config()
    title = f"CTI Alert: {keyword}"
    body = (
        f"Channel: {channel_title}\n"
        f"---\n"
        f"{snippet[:500]}"
    )
    tags = ["warning", "mag"]
    await _send(
        title=title,
        message=body,
        priority=cfg["priority_alert"],
        tags=tags,
    )


async def send_health_warning(status: str, details: str):
    """Push a health warning (scanner down, stale data, etc.)."""
    cfg = await _get_ntfy_config()
    title = f"CTI Scanner: {status}"
    await _send(
        title=title,
        message=details,
        priority=cfg["priority_health"],
        tags=["rotating_light", "skull"],
    )


async def send_health_recovered():
    """Push a recovery notice after a previous health warning."""
    await _send(
        title="CTI Scanner: recovered",
        message="Scanner is back online and receiving messages.",
        priority=3,
        tags=["white_check_mark"],
    )


async def send_retention_report(
    messages_archived: int,
    messages_purged: int,
    iocs_purged: int,
    alerts_purged: int,
    archive_path: str = "",
):
    """Push a summary after a retention run."""
    lines = [
        f"Messages archived: {messages_archived}",
        f"Messages purged: {messages_purged}",
        f"IOCs purged: {iocs_purged}",
        f"Alerts purged: {alerts_purged}",
    ]
    if archive_path:
        lines.append(f"Archive: {archive_path}")

    await _send(
        title="CTI Scanner: retention complete",
        message="\n".join(lines),
        priority=2,
        tags=["broom"],
    )


async def send_discovery_alert(count: int):
    """Push notification when new channel candidates are found."""
    await _send(
        title=f"CTI Scanner: {count} new channel(s) found",
        message=f"{count} new channel candidates discovered.\nReview them in Settings > Discovery.",
        priority=3,
        tags=["satellite"],
    )


async def close():
    global _client
    if _client and not _client.is_closed:
        await _client.aclose()
        _client = None
