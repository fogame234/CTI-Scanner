"""
Health check tracker.

Tracks scanner vitals: connection status, last message time, uptime,
message throughput. Exposes a status dict for the /health endpoint
and pushes ntfy warnings when the scanner goes stale or disconnects.
"""

import logging
import time
from datetime import datetime, timezone

import config
import notify

logger = logging.getLogger(__name__)


class HealthTracker:
    def __init__(self):
        self._start_time: float = time.time()
        self._last_message_at: float = 0.0
        self._last_message_iso: str = ""
        self._messages_total: int = 0
        self._messages_since_check: int = 0
        self._connected: bool = False
        self._warned_stale: bool = False
        self._warned_disconnect: bool = False
        self._last_check: float = time.time()

    # ── Called by scanner on events ───────────────────────────────────

    def record_message(self):
        """Call after each message is processed."""
        now = time.time()
        self._last_message_at = now
        self._last_message_iso = datetime.now(timezone.utc).isoformat()
        self._messages_total += 1
        self._messages_since_check += 1

    def set_connected(self, connected: bool):
        self._connected = connected

    # ── Status snapshot ───────────────────────────────────────────────

    def get_status(self) -> dict:
        now = time.time()
        uptime_s = now - self._start_time
        since_last = now - self._last_message_at if self._last_message_at else None
        check_window = now - self._last_check if self._last_check else uptime_s
        rate = self._messages_since_check / max(check_window, 1)

        # Determine health state
        if not self._connected:
            state = "disconnected"
        elif since_last is None:
            state = "waiting"  # no messages received yet
        elif since_last > config.HEALTH_STALE_THRESHOLD:
            state = "stale"
        else:
            state = "healthy"

        return {
            "status": state,
            "connected": self._connected,
            "uptime_seconds": round(uptime_s),
            "uptime_human": _fmt_duration(uptime_s),
            "last_message_at": self._last_message_iso or None,
            "seconds_since_last_message": round(since_last) if since_last else None,
            "messages_total": self._messages_total,
            "messages_per_minute": round(rate * 60, 1),
            "stale_threshold_seconds": config.HEALTH_STALE_THRESHOLD,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def is_healthy(self) -> bool:
        return self.get_status()["status"] in ("healthy", "waiting")

    # ── Periodic check (call from the scanner loop) ───────────────────

    async def periodic_check(self):
        """
        Run periodically (e.g. every 60s). Sends ntfy warnings when
        the scanner goes stale or disconnects, and recovery notices
        when it comes back.
        """
        status = self.get_status()
        state = status["status"]

        if state == "disconnected" and not self._warned_disconnect:
            await notify.send_health_warning(
                "disconnected",
                f"Telethon client is disconnected.\n"
                f"Uptime was: {status['uptime_human']}\n"
                f"Total messages collected: {status['messages_total']}",
            )
            self._warned_disconnect = True
            self._warned_stale = False

        elif state == "stale" and not self._warned_stale:
            mins = round(status["seconds_since_last_message"] / 60)
            await notify.send_health_warning(
                "stale",
                f"No new messages in {mins} minutes.\n"
                f"Last message: {status['last_message_at']}\n"
                f"Threshold: {config.HEALTH_STALE_THRESHOLD}s\n"
                f"Scanner may have lost its connection silently.",
            )
            self._warned_stale = True

        elif state == "healthy" and (self._warned_stale or self._warned_disconnect):
            await notify.send_health_recovered()
            self._warned_stale = False
            self._warned_disconnect = False

        # Reset rate counter
        self._messages_since_check = 0
        self._last_check = time.time()


# ── Singleton ─────────────────────────────────────────────────────────
_tracker = HealthTracker()

def get_tracker() -> HealthTracker:
    return _tracker


def _fmt_duration(seconds: float) -> str:
    s = int(seconds)
    days, s = divmod(s, 86400)
    hours, s = divmod(s, 3600)
    mins, secs = divmod(s, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if mins:
        parts.append(f"{mins}m")
    parts.append(f"{secs}s")
    return " ".join(parts)
