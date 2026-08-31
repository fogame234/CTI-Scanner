"""
Persistence layer — async SQLite with FTS5 full-text search.

Tables:
  channels        – monitored Telegram channels / groups
  messages         – every message collected from monitored channels
  extracted_iocs   – IOCs pulled from messages (linked back to message)
  alert_keywords   – keywords that trigger notifications
  alerts_fired     – log of triggered alerts
  messages_fts     – FTS5 index over message text
"""

import json
import logging
from datetime import datetime, timezone

import aiosqlite

import config

logger = logging.getLogger(__name__)

_db: aiosqlite.Connection | None = None


# ══════════════════════════════════════════════════════════════════════
#  CONNECTION
# ══════════════════════════════════════════════════════════════════════

async def init() -> aiosqlite.Connection:
    global _db
    if _db is not None:
        return _db
    _db = await aiosqlite.connect(config.DB_PATH)
    _db.row_factory = aiosqlite.Row
    await _db.execute("PRAGMA journal_mode=WAL")
    await _db.execute("PRAGMA foreign_keys=ON")
    await _db.executescript(_SCHEMA)
    await _db.commit()
    logger.info("Database ready: %s", config.DB_PATH)

    # Seed default alert keywords
    for kw in config.DEFAULT_ALERT_KEYWORDS:
        await add_alert_keyword(kw)

    return _db


async def close():
    global _db
    if _db:
        await _db.close()
        _db = None


async def _get() -> aiosqlite.Connection:
    if _db is None:
        return await init()
    return _db


# ══════════════════════════════════════════════════════════════════════
#  SCHEMA
# ══════════════════════════════════════════════════════════════════════

_SCHEMA = """
CREATE TABLE IF NOT EXISTS channels (
    id              INTEGER PRIMARY KEY,        -- Telegram channel ID
    title           TEXT    NOT NULL DEFAULT '',
    username        TEXT    NOT NULL DEFAULT '',  -- @handle (empty if private)
    channel_type    TEXT    NOT NULL DEFAULT '',  -- 'channel', 'megagroup', 'group', 'chat'
    about           TEXT    NOT NULL DEFAULT '',
    participants    INTEGER NOT NULL DEFAULT 0,
    is_monitored    INTEGER NOT NULL DEFAULT 1,
    added_at        TEXT    NOT NULL DEFAULT (datetime('now')),
    last_scraped    TEXT    NOT NULL DEFAULT '',
    notes           TEXT    NOT NULL DEFAULT '',
    tags            TEXT    NOT NULL DEFAULT '[]'  -- JSON array of user tags
);

CREATE TABLE IF NOT EXISTS messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id      INTEGER NOT NULL,
    message_id      INTEGER NOT NULL,             -- Telegram message ID within channel
    sender_id       INTEGER,
    sender_name     TEXT    NOT NULL DEFAULT '',
    date            TEXT    NOT NULL,
    text            TEXT    NOT NULL DEFAULT '',
    has_media       INTEGER NOT NULL DEFAULT 0,
    media_type      TEXT    NOT NULL DEFAULT '',   -- 'photo', 'document', 'video', etc.
    reply_to        INTEGER,                       -- message_id of parent
    forward_from    TEXT    NOT NULL DEFAULT '',    -- original channel/user
    views           INTEGER NOT NULL DEFAULT 0,
    raw_json        TEXT    NOT NULL DEFAULT '{}',
    collected_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(channel_id, message_id)
);

CREATE TABLE IF NOT EXISTS extracted_iocs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    message_rowid   INTEGER NOT NULL REFERENCES messages(id),
    channel_id      INTEGER NOT NULL,
    ioc_type        TEXT    NOT NULL,   -- ipv4, domain, sha256, btc, onion, cve …
    value           TEXT    NOT NULL,
    first_seen      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(message_rowid, ioc_type, value)
);

CREATE TABLE IF NOT EXISTS alert_keywords (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    keyword         TEXT    NOT NULL UNIQUE,
    is_regex        INTEGER NOT NULL DEFAULT 0,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alerts_fired (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    keyword_id      INTEGER NOT NULL REFERENCES alert_keywords(id),
    message_rowid   INTEGER NOT NULL REFERENCES messages(id),
    channel_id      INTEGER NOT NULL,
    snippet         TEXT    NOT NULL DEFAULT '',
    fired_at        TEXT    NOT NULL DEFAULT (datetime('now')),
    acknowledged    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS stealer_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    message_rowid   INTEGER NOT NULL REFERENCES messages(id),
    channel_id      INTEGER NOT NULL,
    channel_title   TEXT    NOT NULL DEFAULT '',
    date            TEXT    NOT NULL,
    confidence      REAL    NOT NULL DEFAULT 0.0,
    families        TEXT    NOT NULL DEFAULT '[]',   -- JSON array: ["RedLine", "Vidar"]
    log_count       INTEGER,
    countries       TEXT    NOT NULL DEFAULT '[]',   -- JSON array: ["US", "DE"]
    data_types      TEXT    NOT NULL DEFAULT '[]',   -- JSON array: ["passwords", "cookies"]
    price_usd       TEXT    NOT NULL DEFAULT '',
    sender_name     TEXT    NOT NULL DEFAULT '',
    message_text    TEXT    NOT NULL DEFAULT '',
    collected_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(message_rowid)
);

CREATE TABLE IF NOT EXISTS discovery_candidates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id      INTEGER NOT NULL,
    title           TEXT    NOT NULL DEFAULT '',
    username        TEXT    NOT NULL DEFAULT '',
    channel_type    TEXT    NOT NULL DEFAULT '',
    about           TEXT    NOT NULL DEFAULT '',
    participants    INTEGER NOT NULL DEFAULT 0,
    search_term     TEXT    NOT NULL DEFAULT '',  -- what query found this
    status          TEXT    NOT NULL DEFAULT 'pending',  -- pending, approved, dismissed
    discovered_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    reviewed_at     TEXT    NOT NULL DEFAULT '',
    UNIQUE(channel_id)
);

CREATE TABLE IF NOT EXISTS scanner_settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_msg_channel     ON messages(channel_id);
CREATE INDEX IF NOT EXISTS idx_msg_date        ON messages(date);
CREATE INDEX IF NOT EXISTS idx_ioc_type        ON extracted_iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_value       ON extracted_iocs(value);
CREATE INDEX IF NOT EXISTS idx_ioc_channel     ON extracted_iocs(channel_id);
CREATE INDEX IF NOT EXISTS idx_alerts_ack      ON alerts_fired(acknowledged);
CREATE INDEX IF NOT EXISTS idx_stealer_channel ON stealer_logs(channel_id);
CREATE INDEX IF NOT EXISTS idx_stealer_date    ON stealer_logs(date);
CREATE INDEX IF NOT EXISTS idx_stealer_family  ON stealer_logs(families);

-- FTS5 over message text
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    channel_title,
    sender_name,
    text,
    content='messages',
    content_rowid='id',
    tokenize='porter unicode61'
);

-- Triggers to keep FTS in sync
CREATE TRIGGER IF NOT EXISTS msg_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, channel_title, sender_name, text)
    VALUES (
        new.id,
        COALESCE((SELECT title FROM channels WHERE id = new.channel_id), ''),
        new.sender_name,
        new.text
    );
END;

CREATE TRIGGER IF NOT EXISTS msg_ad AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, channel_title, sender_name, text)
    VALUES (
        'delete',
        old.id,
        COALESCE((SELECT title FROM channels WHERE id = old.channel_id), ''),
        old.sender_name,
        old.text
    );
END;
"""


# ══════════════════════════════════════════════════════════════════════
#  CHANNELS
# ══════════════════════════════════════════════════════════════════════

async def upsert_channel(
    channel_id: int, title: str, username: str = "",
    channel_type: str = "", about: str = "",
    participants: int = 0, tags: list[str] | None = None,
    notes: str = "",
) -> None:
    db = await _get()
    await db.execute(
        """INSERT INTO channels (id, title, username, channel_type, about,
           participants, tags, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             title = excluded.title,
             username = excluded.username,
             channel_type = excluded.channel_type,
             about = excluded.about,
             participants = excluded.participants,
             tags = CASE WHEN excluded.tags != '[]' THEN excluded.tags ELSE channels.tags END,
             notes = CASE WHEN excluded.notes != '' THEN excluded.notes ELSE channels.notes END
        """,
        (channel_id, title, username, channel_type, about,
         participants, json.dumps(tags or []), notes),
    )
    await db.commit()


async def set_monitored(channel_id: int, monitored: bool) -> None:
    db = await _get()
    await db.execute(
        "UPDATE channels SET is_monitored = ? WHERE id = ?",
        (1 if monitored else 0, channel_id),
    )
    await db.commit()


async def get_monitored_channels() -> list[dict]:
    db = await _get()
    rows = await db.execute_fetchall(
        "SELECT * FROM channels WHERE is_monitored = 1"
    )
    return [_parse_channel(r) for r in rows]


async def get_all_channels() -> list[dict]:
    db = await _get()
    rows = await db.execute_fetchall("SELECT * FROM channels ORDER BY added_at DESC")
    return [_parse_channel(r) for r in rows]


async def get_channel(channel_id: int) -> dict | None:
    db = await _get()
    rows = await db.execute_fetchall("SELECT * FROM channels WHERE id = ?", (channel_id,))
    return _parse_channel(rows[0]) if rows else None


async def update_last_scraped(channel_id: int, ts: str) -> None:
    db = await _get()
    await db.execute("UPDATE channels SET last_scraped = ? WHERE id = ?", (ts, channel_id))
    await db.commit()


def _parse_channel(row) -> dict:
    d = dict(row)
    d["tags"] = json.loads(d.get("tags", "[]"))
    return d


# ══════════════════════════════════════════════════════════════════════
#  MESSAGES
# ══════════════════════════════════════════════════════════════════════

async def store_message(
    channel_id: int, message_id: int, sender_id: int | None,
    sender_name: str, date: str, text: str,
    has_media: bool = False, media_type: str = "",
    reply_to: int | None = None, forward_from: str = "",
    views: int = 0, raw_json: dict | None = None,
) -> int | None:
    """Store a message. Returns row ID, or None if duplicate."""
    db = await _get()
    try:
        cursor = await db.execute(
            """INSERT INTO messages
               (channel_id, message_id, sender_id, sender_name, date, text,
                has_media, media_type, reply_to, forward_from, views, raw_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (channel_id, message_id, sender_id, sender_name, date, text,
             1 if has_media else 0, media_type, reply_to, forward_from,
             views, json.dumps(raw_json or {})),
        )
        await db.commit()
        return cursor.lastrowid
    except aiosqlite.IntegrityError:
        return None  # duplicate


async def store_iocs(message_rowid: int, channel_id: int,
                      iocs: list[tuple[str, str]]) -> int:
    """Store extracted IOCs from a message. Returns count stored."""
    db = await _get()
    count = 0
    for ioc_type, value in iocs:
        try:
            await db.execute(
                """INSERT OR IGNORE INTO extracted_iocs
                   (message_rowid, channel_id, ioc_type, value)
                   VALUES (?, ?, ?, ?)""",
                (message_rowid, channel_id, ioc_type, value),
            )
            count += 1
        except aiosqlite.IntegrityError:
            pass
    await db.commit()
    return count


async def get_channel_messages(channel_id: int, limit: int = 100,
                                offset: int = 0) -> list[dict]:
    db = await _get()
    rows = await db.execute_fetchall(
        "SELECT * FROM messages WHERE channel_id = ? ORDER BY date DESC LIMIT ? OFFSET ?",
        (channel_id, limit, offset),
    )
    return [dict(r) for r in rows]


async def get_message(rowid: int) -> dict | None:
    db = await _get()
    rows = await db.execute_fetchall("SELECT * FROM messages WHERE id = ?", (rowid,))
    return dict(rows[0]) if rows else None


# ══════════════════════════════════════════════════════════════════════
#  IOC QUERIES
# ══════════════════════════════════════════════════════════════════════

async def search_iocs(ioc_type: str | None = None, value: str | None = None,
                       channel_id: int | None = None, limit: int = 100) -> list[dict]:
    db = await _get()
    sql = "SELECT e.*, m.text, m.date, c.title AS channel_title FROM extracted_iocs e " \
          "JOIN messages m ON e.message_rowid = m.id " \
          "JOIN channels c ON e.channel_id = c.id WHERE 1=1"
    params: list = []
    if ioc_type:
        sql += " AND e.ioc_type = ?"
        params.append(ioc_type)
    if value:
        sql += " AND e.value LIKE ?"
        params.append(f"%{value}%")
    if channel_id is not None:
        sql += " AND e.channel_id = ?"
        params.append(channel_id)
    sql += " ORDER BY e.first_seen DESC LIMIT ?"
    params.append(limit)
    rows = await db.execute_fetchall(sql, params)
    return [dict(r) for r in rows]


async def get_ioc_summary() -> list[dict]:
    """Counts by IOC type."""
    db = await _get()
    rows = await db.execute_fetchall(
        "SELECT ioc_type, COUNT(DISTINCT value) AS unique_count, COUNT(*) AS total "
        "FROM extracted_iocs GROUP BY ioc_type ORDER BY unique_count DESC"
    )
    return [dict(r) for r in rows]


async def get_ioc_timeline(ioc_value: str) -> list[dict]:
    """All sightings of a specific IOC value across channels."""
    db = await _get()
    rows = await db.execute_fetchall(
        """SELECT e.ioc_type, e.first_seen, c.title AS channel_title,
                  c.username AS channel_username, m.text, m.date
           FROM extracted_iocs e
           JOIN messages m ON e.message_rowid = m.id
           JOIN channels c ON e.channel_id = c.id
           WHERE e.value = ?
           ORDER BY m.date DESC""",
        (ioc_value,),
    )
    return [dict(r) for r in rows]


# ══════════════════════════════════════════════════════════════════════
#  FULL-TEXT SEARCH
# ══════════════════════════════════════════════════════════════════════

async def search_messages(query: str, limit: int = 50) -> list[dict]:
    """FTS5 search across all collected messages."""
    db = await _get()
    # Sanitize query for FTS5 — strip special characters that crash it,
    # wrap each word in double quotes to treat as literal terms
    sanitized = _sanitize_fts(query)
    if not sanitized:
        return []
    try:
        rows = await db.execute_fetchall(
            """SELECT m.id, m.channel_id, m.message_id, m.sender_name, m.date,
                      snippet(messages_fts, 2, '»', '«', '…', 48) AS snippet,
                      c.title AS channel_title, c.username AS channel_username,
                      rank
               FROM messages_fts
               JOIN messages m ON messages_fts.rowid = m.id
               JOIN channels c ON m.channel_id = c.id
               WHERE messages_fts MATCH ?
               ORDER BY rank
               LIMIT ?""",
            (sanitized, limit),
        )
        return [dict(r) for r in rows]
    except Exception as e:
        logger.warning("FTS search failed for '%s': %s", query, e)
        # Fallback to LIKE search
        try:
            rows = await db.execute_fetchall(
                """SELECT m.id, m.channel_id, m.message_id, m.sender_name, m.date,
                          substr(m.text, 1, 150) AS snippet,
                          c.title AS channel_title, c.username AS channel_username,
                          0 AS rank
                   FROM messages m
                   JOIN channels c ON m.channel_id = c.id
                   WHERE m.text LIKE ?
                   ORDER BY m.date DESC
                   LIMIT ?""",
                (f"%{query}%", limit),
            )
            return [dict(r) for r in rows]
        except Exception:
            return []


def _sanitize_fts(query: str) -> str:
    """Sanitize a query string for FTS5 MATCH.
    Wraps each token in double quotes so special chars are treated literally."""
    import re as _re
    # Remove characters that break FTS5 syntax
    cleaned = _re.sub(r'["\'\(\)\*\{\}\[\]:^~]', ' ', query)
    tokens = cleaned.split()
    if not tokens:
        return ""
    # Wrap each token in quotes for literal matching
    return " ".join(f'"{t}"' for t in tokens if t)


# ══════════════════════════════════════════════════════════════════════
#  ALERT KEYWORDS
# ══════════════════════════════════════════════════════════════════════

async def add_alert_keyword(keyword: str, is_regex: bool = False) -> int | None:
    db = await _get()
    try:
        cursor = await db.execute(
            "INSERT INTO alert_keywords (keyword, is_regex) VALUES (?, ?)",
            (keyword.lower().strip(), 1 if is_regex else 0),
        )
        await db.commit()
        return cursor.lastrowid
    except aiosqlite.IntegrityError:
        return None


async def remove_alert_keyword(keyword: str) -> bool:
    db = await _get()
    cursor = await db.execute(
        "DELETE FROM alert_keywords WHERE keyword = ?", (keyword.lower().strip(),)
    )
    await db.commit()
    return cursor.rowcount > 0


async def get_alert_keywords() -> list[dict]:
    db = await _get()
    rows = await db.execute_fetchall(
        "SELECT * FROM alert_keywords WHERE enabled = 1"
    )
    return [dict(r) for r in rows]


async def fire_alert(keyword_id: int, message_rowid: int,
                      channel_id: int, snippet: str) -> int:
    db = await _get()
    cursor = await db.execute(
        "INSERT INTO alerts_fired (keyword_id, message_rowid, channel_id, snippet) "
        "VALUES (?, ?, ?, ?)",
        (keyword_id, message_rowid, channel_id, snippet),
    )
    await db.commit()
    return cursor.lastrowid


async def get_recent_alerts(limit: int = 50, unack_only: bool = False) -> list[dict]:
    db = await _get()
    sql = """SELECT a.*, k.keyword, c.title AS channel_title
             FROM alerts_fired a
             JOIN alert_keywords k ON a.keyword_id = k.id
             JOIN channels c ON a.channel_id = c.id"""
    if unack_only:
        sql += " WHERE a.acknowledged = 0"
    sql += " ORDER BY a.fired_at DESC LIMIT ?"
    rows = await db.execute_fetchall(sql, (limit,))
    return [dict(r) for r in rows]


async def acknowledge_alert(alert_id: int) -> None:
    db = await _get()
    await db.execute("UPDATE alerts_fired SET acknowledged = 1 WHERE id = ?", (alert_id,))
    await db.commit()


# ══════════════════════════════════════════════════════════════════════
#  STATS / EXPORT
# ══════════════════════════════════════════════════════════════════════

async def get_stats() -> dict:
    db = await _get()
    stats = {}
    for table, key in [("channels", "channels"), ("messages", "messages"),
                        ("extracted_iocs", "iocs"), ("alerts_fired", "alerts")]:
        rows = await db.execute_fetchall(f"SELECT COUNT(*) AS cnt FROM {table}")
        stats[key] = rows[0]["cnt"]

    rows = await db.execute_fetchall(
        "SELECT COUNT(*) AS cnt FROM channels WHERE is_monitored = 1"
    )
    stats["monitored"] = rows[0]["cnt"]

    rows = await db.execute_fetchall(
        "SELECT COUNT(*) AS cnt FROM alerts_fired WHERE acknowledged = 0"
    )
    stats["unack_alerts"] = rows[0]["cnt"]

    return stats


async def export_all() -> dict:
    db = await _get()
    channels = await db.execute_fetchall("SELECT * FROM channels")
    ioc_summary = await get_ioc_summary()
    recent_alerts = await get_recent_alerts(200)
    stats = await get_stats()

    # Redact keyword text from alerts to avoid revealing collection posture
    safe_alerts = []
    for a in recent_alerts:
        sa = dict(a)
        sa.pop("keyword", None)
        safe_alerts.append(sa)

    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "stats": stats,
        "channels": [_parse_channel(r) for r in channels],
        "ioc_summary": ioc_summary,
        "recent_alerts": safe_alerts,
        # scanner_settings intentionally excluded - contains secrets
    }


# ══════════════════════════════════════════════════════════════════════
#  STEALER LOGS
# ══════════════════════════════════════════════════════════════════════

async def store_stealer_log(
    message_rowid: int, channel_id: int, channel_title: str,
    date: str, sender_name: str, message_text: str,
    confidence: float, families: list[str], log_count: int | None,
    countries: list[str], data_types: list[str], price_usd: str,
    has_download: bool = False, download_type: str = "",
) -> int | None:
    """Store a parsed stealer log entry. Returns row ID or None if duplicate."""
    db = await _get()
    try:
        cursor = await db.execute(
            """INSERT INTO stealer_logs
               (message_rowid, channel_id, channel_title, date, confidence,
                families, log_count, countries, data_types, price_usd,
                sender_name, message_text, has_download, download_type)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (message_rowid, channel_id, channel_title, date, confidence,
             json.dumps(families), log_count, json.dumps(countries),
             json.dumps(data_types), price_usd, sender_name,
             message_text[:2000], 1 if has_download else 0, download_type),
        )
        await db.commit()
        return cursor.lastrowid
    except aiosqlite.IntegrityError:
        return None


async def get_stealer_logs(
    channel_id: int | None = None,
    family: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Query stealer log entries with optional filters."""
    db = await _get()
    sql = "SELECT * FROM stealer_logs WHERE 1=1"
    params: list = []
    if channel_id is not None:
        sql += " AND channel_id = ?"
        params.append(channel_id)
    if family:
        sql += " AND families LIKE ?"
        params.append(f"%{family}%")
    sql += " ORDER BY date DESC LIMIT ?"
    params.append(limit)
    rows = await db.execute_fetchall(sql, params)
    return [_parse_stealer_row(r) for r in rows]


async def get_stealer_log_stats() -> dict:
    """Aggregate stats for stealer logs."""
    db = await _get()

    rows = await db.execute_fetchall("SELECT COUNT(*) AS cnt FROM stealer_logs")
    total = rows[0]["cnt"]

    # By channel
    rows = await db.execute_fetchall(
        "SELECT channel_title, COUNT(*) AS cnt FROM stealer_logs "
        "GROUP BY channel_title ORDER BY cnt DESC LIMIT 20"
    )
    by_channel = {r["channel_title"]: r["cnt"] for r in rows}

    # By family (requires parsing JSON — do in Python)
    rows = await db.execute_fetchall("SELECT families FROM stealer_logs")
    family_counts: dict[str, int] = {}
    for r in rows:
        for fam in json.loads(r["families"]):
            family_counts[fam] = family_counts.get(fam, 0) + 1

    return {
        "total": total,
        "by_channel": by_channel,
        "by_family": dict(sorted(family_counts.items(), key=lambda x: -x[1])),
    }


def _parse_stealer_row(row) -> dict:
    d = dict(row)
    for field in ("families", "countries", "data_types"):
        d[field] = json.loads(d.get(field, "[]"))
    return d

# ══════════════════════════════════════════════════════════════════════
#  DISCOVERY CANDIDATES
# ══════════════════════════════════════════════════════════════════════

async def add_candidate(
    channel_id: int, title: str, username: str,
    channel_type: str, about: str, participants: int,
    search_term: str,
) -> int | None:
    """Add a discovered channel candidate. Returns row ID or None if duplicate."""
    db = await _get()
    try:
        cursor = await db.execute(
            """INSERT INTO discovery_candidates
               (channel_id, title, username, channel_type, about,
                participants, search_term)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (channel_id, title, username, channel_type, about,
             participants, search_term),
        )
        await db.commit()
        return cursor.lastrowid
    except aiosqlite.IntegrityError:
        return None  # already known


async def get_candidates(status: str = "pending", limit: int = 50) -> list[dict]:
    db = await _get()
    rows = await db.execute_fetchall(
        "SELECT * FROM discovery_candidates WHERE status = ? ORDER BY discovered_at DESC LIMIT ?",
        (status, limit),
    )
    return [dict(r) for r in rows]


async def get_candidate_counts() -> dict:
    db = await _get()
    rows = await db.execute_fetchall(
        "SELECT status, COUNT(*) AS cnt FROM discovery_candidates GROUP BY status"
    )
    return {r["status"]: r["cnt"] for r in rows}


async def set_candidate_status(channel_id: int, status: str) -> None:
    db = await _get()
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "UPDATE discovery_candidates SET status = ?, reviewed_at = ? WHERE channel_id = ?",
        (status, now, channel_id),
    )
    await db.commit()


async def is_known_channel(channel_id: int) -> bool:
    """Check if a channel is already monitored or a known candidate."""
    db = await _get()
    rows = await db.execute_fetchall(
        "SELECT id FROM channels WHERE id = ?", (channel_id,)
    )
    if rows:
        return True
    rows = await db.execute_fetchall(
        "SELECT id FROM discovery_candidates WHERE channel_id = ?", (channel_id,)
    )
    return bool(rows)

# ══════════════════════════════════════════════════════════════════════
#  SCANNER SETTINGS (runtime-configurable)
# ══════════════════════════════════════════════════════════════════════

async def get_setting(key: str, default: str = "") -> str:
    from secret_store import is_sensitive, decrypt
    db = await _get()
    rows = await db.execute_fetchall(
        "SELECT value FROM scanner_settings WHERE key = ?", (key,)
    )
    if not rows:
        return default
    value = rows[0]["value"]
    if is_sensitive(key):
        value = decrypt(value)
    return value


async def set_setting(key: str, value: str) -> None:
    from secret_store import is_sensitive, encrypt
    db = await _get()
    store_value = value
    if is_sensitive(key) and value:
        store_value = encrypt(value)
    await db.execute(
        "INSERT INTO scanner_settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, store_value),
    )
    await db.commit()


async def get_all_settings() -> dict:
    """Get all settings, decrypting sensitive values."""
    from secret_store import is_sensitive, decrypt
    db = await _get()
    rows = await db.execute_fetchall("SELECT key, value FROM scanner_settings")
    result = {}
    for r in rows:
        key, value = r["key"], r["value"]
        if is_sensitive(key):
            value = decrypt(value)
        result[key] = value
    return result

# ══════════════════════════════════════════════════════════════════════
#  DASHBOARD QUERIES
# ══════════════════════════════════════════════════════════════════════

async def get_iocs_per_day(days: int = 30) -> list[dict]:
    """IOC count per day for the last N days."""
    db = await _get()
    rows = await db.execute_fetchall(
        """SELECT date(first_seen) AS day, COUNT(*) AS count
           FROM extracted_iocs
           WHERE first_seen >= datetime('now', ?)
           GROUP BY date(first_seen)
           ORDER BY day ASC""",
        (f"-{days} days",),
    )
    return [dict(r) for r in rows]


async def get_top_iocs(limit: int = 10) -> list[dict]:
    """Most-seen IOC values across all channels."""
    db = await _get()
    rows = await db.execute_fetchall(
        """SELECT e.value, e.ioc_type,
                  COUNT(*) AS sightings,
                  COUNT(DISTINCT e.channel_id) AS channels,
                  MIN(e.first_seen) AS first_seen,
                  MAX(e.first_seen) AS last_seen
           FROM extracted_iocs e
           GROUP BY e.value
           ORDER BY channels DESC, sightings DESC
           LIMIT ?""",
        (limit,),
    )
    return [dict(r) for r in rows]


async def get_recent_iocs(limit: int = 10) -> list[dict]:
    """Most recently extracted unique IOCs."""
    db = await _get()
    rows = await db.execute_fetchall(
        """SELECT e.value, e.ioc_type, e.first_seen,
                  c.title AS channel_title
           FROM extracted_iocs e
           JOIN channels c ON e.channel_id = c.id
           GROUP BY e.value
           HAVING e.first_seen = MAX(e.first_seen)
           ORDER BY e.first_seen DESC
           LIMIT ?""",
        (limit,),
    )
    return [dict(r) for r in rows]


async def get_active_channels(days: int = 7, limit: int = 8) -> list[dict]:
    """Channels with the most messages in the last N days."""
    db = await _get()
    rows = await db.execute_fetchall(
        """SELECT c.id, c.title, c.username, COUNT(m.id) AS msg_count
           FROM messages m
           JOIN channels c ON m.channel_id = c.id
           WHERE m.date >= datetime('now', ?)
           GROUP BY c.id
           ORDER BY msg_count DESC
           LIMIT ?""",
        (f"-{days} days", limit),
    )
    return [dict(r) for r in rows]


async def get_stealer_family_counts(days: int = 30) -> dict:
    """Stealer family counts from the last N days."""
    db = await _get()
    rows = await db.execute_fetchall(
        "SELECT families FROM stealer_logs WHERE date >= datetime('now', ?)",
        (f"-{days} days",),
    )
    counts: dict[str, int] = {}
    for r in rows:
        for fam in json.loads(r["families"]):
            counts[fam] = counts.get(fam, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))
