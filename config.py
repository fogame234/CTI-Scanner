"""
Configuration for the CTI Telegram Scanner.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

# ── Telegram Client API (from https://my.telegram.org) ───────────────
# You MUST use the client API (not the bot API) to search/join/read channels.
API_ID    = int(os.getenv("TELEGRAM_API_ID", "0"))
API_HASH  = os.getenv("TELEGRAM_API_HASH", "")
PHONE     = os.getenv("TELEGRAM_PHONE", "")          # +1234567890
SESSION   = os.getenv("SESSION_NAME", "cti_scanner")  # Telethon session file

# ── Optional: Bot token for a command interface ───────────────────────
# If set, a companion bot runs alongside the scanner so you can
# issue /scan, /monitor, /search commands from any Telegram chat.
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")

# ── Database backend ──────────────────────────────────────────────────
# Set DB_BACKEND to 'elasticsearch' or 'sqlite'
DB_BACKEND = os.getenv("DB_BACKEND", "sqlite")
DB_PATH    = os.getenv("DB_PATH", str(Path(__file__).parent / "cti_scanner.db"))

# ── Elasticsearch ─────────────────────────────────────────────────────
ES_HOSTS      = os.getenv("ES_HOSTS", "http://localhost:9200").split(",")
ES_USERNAME   = os.getenv("ES_USERNAME", "")
ES_PASSWORD   = os.getenv("ES_PASSWORD", "")
ES_API_KEY    = os.getenv("ES_API_KEY", "")          # alternative to user/pass
ES_CA_CERTS   = os.getenv("ES_CA_CERTS", "")         # path to CA cert for TLS
ES_VERIFY     = os.getenv("ES_VERIFY", "true").lower() in ("true", "1", "yes")
ES_PREFIX     = os.getenv("ES_INDEX_PREFIX", "cti")   # index prefix: cti-channels, cti-messages, …

# ── Web UI ────────────────────────────────────────────────────────────
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("WEB_PORT", "8080"))

# ── Scanner settings ─────────────────────────────────────────────────
# How often (seconds) to re-scan monitored channels for history backfill
BACKFILL_INTERVAL = int(os.getenv("BACKFILL_INTERVAL", "3600"))

# Max messages to pull per channel on first join / backfill
BACKFILL_LIMIT = int(os.getenv("BACKFILL_LIMIT", "500"))

# ── Default alert keywords (comma-separated) ─────────────────────────
# New messages matching any keyword trigger a notification.
_kw = os.getenv("ALERT_KEYWORDS", "")
DEFAULT_ALERT_KEYWORDS: list[str] = [
    k.strip().lower() for k in _kw.split(",") if k.strip()
]

# ── ntfy notifications ───────────────────────────────────────────────
NTFY_URL   = os.getenv("NTFY_URL", "")            # e.g. https://ntfy.example.com
NTFY_TOPIC = os.getenv("NTFY_TOPIC", "cti-alerts") # topic name
NTFY_TOKEN = os.getenv("NTFY_TOKEN", "")           # access token (if auth enabled)

# Alert priority mapping (ntfy priorities: 1=min, 2=low, 3=default, 4=high, 5=urgent)
NTFY_PRIORITY_ALERT  = int(os.getenv("NTFY_PRIORITY_ALERT", "4"))
NTFY_PRIORITY_HEALTH = int(os.getenv("NTFY_PRIORITY_HEALTH", "5"))

# ── Data retention / archival ─────────────────────────────────────────
# Messages older than RETAIN_DAYS are archived then purged.
RETAIN_DAYS       = int(os.getenv("RETAIN_DAYS", "90"))
# IOCs older than RETAIN_IOCS_DAYS are purged (usually keep longer than messages).
RETAIN_IOCS_DAYS  = int(os.getenv("RETAIN_IOCS_DAYS", "180"))
# Fired alerts older than this are purged.
RETAIN_ALERTS_DAYS = int(os.getenv("RETAIN_ALERTS_DAYS", "90"))
# Where to write compressed JSON archives before purging.
ARCHIVE_DIR       = os.getenv("ARCHIVE_DIR", str(Path(__file__).parent / "archives"))
# How often (seconds) the retention job runs. Default: once per day.
RETENTION_INTERVAL = int(os.getenv("RETENTION_INTERVAL", "86400"))

# ── Health check ──────────────────────────────────────────────────────
# If no new message arrives within this many seconds, health goes stale.
HEALTH_STALE_THRESHOLD = int(os.getenv("HEALTH_STALE_THRESHOLD", "600"))

# ── Auto-discovery ────────────────────────────────────────────────────
# Comma-separated search terms to periodically search for new channels.
_disc = os.getenv("DISCOVERY_KEYWORDS", "")
DISCOVERY_KEYWORDS: list[str] = [
    k.strip() for k in _disc.split(",") if k.strip()
]
# How often (seconds) to run auto-discovery. Default: every 6 hours.
DISCOVERY_INTERVAL = int(os.getenv("DISCOVERY_INTERVAL", "21600"))
# Minimum members for a discovered channel to be worth showing.
DISCOVERY_MIN_MEMBERS = int(os.getenv("DISCOVERY_MIN_MEMBERS", "100"))

# ── Filters ───────────────────────────────────────────────────────────
# Messages shorter than this are discarded (cuts out "ok", "yes", emoji-only)
FILTER_MIN_MSG_LENGTH = os.getenv("FILTER_MIN_MSG_LENGTH", "10")

# Spam patterns (pipe-separated regex). Messages matching any are discarded.
# Default patterns catch VIP bait, fake giveaways, and earn-money spam.
FILTER_SPAM_PATTERNS = os.getenv("FILTER_SPAM_PATTERNS", "")

# IOC types to extract (comma-separated). Empty = all types.
# Options: ipv4,ipv6,domain,url,md5,sha1,sha256,email,cve,onion,btc,eth,xmr
FILTER_IOC_TYPES = os.getenv("FILTER_IOC_TYPES", "")

# Skip private/internal IPs (10.x, 172.16-31.x, 192.168.x, 127.x)
FILTER_SKIP_PRIVATE_IPS = os.getenv("FILTER_SKIP_PRIVATE_IPS", "true")

# Extra domains to ignore (comma-separated), on top of built-in FP list
FILTER_IGNORE_DOMAINS = os.getenv("FILTER_IGNORE_DOMAINS", "")

# Stealer log minimum confidence (0.0-1.0). Lower = more logs, more noise.
FILTER_STEALER_MIN_CONFIDENCE = os.getenv("FILTER_STEALER_MIN_CONFIDENCE", "0.35")

# Only store stealer logs that have a download link
FILTER_STEALER_REQUIRE_DOWNLOAD = os.getenv("FILTER_STEALER_REQUIRE_DOWNLOAD", "false")
