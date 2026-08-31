"""
Message and IOC filters — runtime configurable.

Filter settings are stored in the database (scanner_settings table)
and can be toggled from the Settings page without restarting.

The scanner calls these filters before storing messages, IOCs,
and stealer logs. Anything that fails a filter is silently dropped.
"""

import re
import logging

logger = logging.getLogger(__name__)

# ── In-memory filter state (refreshed from DB periodically) ───────────

_settings: dict[str, str] = {}
_spam_patterns: list[re.Pattern] = []

# Default spam patterns
_DEFAULT_SPAM = [
    r"join\s+(vip|premium)\s+(for|to)\s+",
    r"subscribe\s+to\s+(unlock|access)",
    r"(click|tap)\s+here\s+to\s+(join|subscribe)",
    r"free\s+(netflix|spotify|paypal|amazon)\s+account",
    r"(earn|make)\s+\$?\d+.*per\s+(day|hour|week)",
    r"(dm|message)\s+me\s+for\s+(price|deal|offer)",
]

_PRIVATE_IP_PATTERNS = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^169\.254\."),
]

# ── Default settings (used until DB values are loaded) ────────────────
DEFAULTS = {
    "filter_enabled":               "true",
    "filter_relevance_only":        "true",   # only store messages with IOCs/keywords/stealer
    "filter_min_msg_length":        "10",
    "filter_spam_enabled":          "true",
    "filter_skip_private_ips":      "true",
    "filter_ioc_types":             "",       # empty = all types
    "filter_ignore_domains":        "",
    "filter_stealer_min_confidence": "0.35",
    "filter_stealer_require_download": "false",
}


def _get(key: str) -> str:
    return _settings.get(key, DEFAULTS.get(key, ""))


def _bool(key: str) -> bool:
    return _get(key).lower() in ("true", "1", "yes")


async def load_from_db():
    """Load filter settings from the database. Call on startup and periodically."""
    global _settings, _spam_patterns
    try:
        import db_router as db
        _settings = await db.get_all_settings()
    except Exception:
        _settings = {}

    # Compile spam patterns
    _spam_patterns = []
    for p in _DEFAULT_SPAM:
        try:
            _spam_patterns.append(re.compile(p, re.IGNORECASE))
        except re.error:
            pass


async def seed_defaults():
    """Write default settings to DB if they don't exist yet."""
    import db_router as db
    for key, default in DEFAULTS.items():
        existing = await db.get_setting(key, "")
        if not existing:
            await db.set_setting(key, default)
    await load_from_db()


# ══════════════════════════════════════════════════════════════════════
#  FILTER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════

def is_enabled() -> bool:
    """Master switch — if off, nothing is filtered."""
    return _bool("filter_enabled")


def relevance_only() -> bool:
    """If true, only store messages with IOCs, keyword matches, or stealer log content."""
    return _bool("filter_relevance_only")


def should_store_message(text: str) -> bool:
    """Pre-check: message length and spam patterns. Called before IOC extraction."""
    if not is_enabled():
        return True

    if not text or len(text.strip()) < int(_get("filter_min_msg_length")):
        return False

    if _bool("filter_spam_enabled"):
        for pattern in _spam_patterns:
            if pattern.search(text):
                return False

    return True


def should_store_after_extraction(has_iocs: bool, has_keyword_match: bool,
                                    is_stealer_log: bool) -> bool:
    """
    Post-check: called after IOC extraction and keyword matching.
    If relevance_only is on, the message is only kept if it has
    at least one useful signal.
    """
    if not is_enabled():
        return True

    if not relevance_only():
        return True

    return has_iocs or has_keyword_match or is_stealer_log


def filter_iocs(iocs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Filter IOCs by type and value rules."""
    if not is_enabled():
        return iocs

    allowed_types_raw = _get("filter_ioc_types")
    allowed_types = set()
    if allowed_types_raw:
        allowed_types = {t.strip().lower() for t in allowed_types_raw.split(",") if t.strip()}

    ignore_domains_raw = _get("filter_ignore_domains")
    ignore_domains = set()
    if ignore_domains_raw:
        ignore_domains = {d.strip().lower() for d in ignore_domains_raw.split(",") if d.strip()}

    skip_private = _bool("filter_skip_private_ips")

    filtered = []
    for ioc_type, value in iocs:
        if allowed_types and ioc_type not in allowed_types:
            continue

        if skip_private and ioc_type == "ipv4":
            if any(p.match(value) for p in _PRIVATE_IP_PATTERNS):
                continue

        if ioc_type == "domain" and value.lower() in ignore_domains:
            continue

        filtered.append((ioc_type, value))

    return filtered


def should_store_stealer_log(confidence: float, has_download: bool) -> bool:
    """Check stealer log against confidence and download filters."""
    if not is_enabled():
        return True

    min_conf = float(_get("filter_stealer_min_confidence"))
    if confidence < min_conf:
        return False

    if _bool("filter_stealer_require_download") and not has_download:
        return False

    return True


def get_filter_status() -> dict:
    """Return current filter config for the settings page."""
    allowed = _get("filter_ioc_types")
    return {
        "enabled": _bool("filter_enabled"),
        "relevance_only": _bool("filter_relevance_only"),
        "min_message_length": int(_get("filter_min_msg_length")),
        "spam_enabled": _bool("filter_spam_enabled"),
        "spam_patterns": len(_spam_patterns),
        "allowed_ioc_types": sorted(t.strip() for t in allowed.split(",") if t.strip()) if allowed else ["all"],
        "skip_private_ips": _bool("filter_skip_private_ips"),
        "extra_ignore_domains": _get("filter_ignore_domains"),
        "stealer_min_confidence": float(_get("filter_stealer_min_confidence")),
        "stealer_require_download": _bool("filter_stealer_require_download"),
    }
