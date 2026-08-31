#!/usr/bin/env python3
"""Run this once to add any missing tables to an existing database."""
import sqlite3
import config

conn = sqlite3.connect(config.DB_PATH)

conn.executescript("""
CREATE TABLE IF NOT EXISTS discovery_candidates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id      INTEGER NOT NULL,
    title           TEXT    NOT NULL DEFAULT '',
    username        TEXT    NOT NULL DEFAULT '',
    channel_type    TEXT    NOT NULL DEFAULT '',
    about           TEXT    NOT NULL DEFAULT '',
    participants    INTEGER NOT NULL DEFAULT 0,
    search_term     TEXT    NOT NULL DEFAULT '',
    status          TEXT    NOT NULL DEFAULT 'pending',
    discovered_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    reviewed_at     TEXT    NOT NULL DEFAULT '',
    UNIQUE(channel_id)
);

CREATE TABLE IF NOT EXISTS stealer_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    message_rowid   INTEGER NOT NULL REFERENCES messages(id),
    channel_id      INTEGER NOT NULL,
    channel_title   TEXT    NOT NULL DEFAULT '',
    date            TEXT    NOT NULL,
    confidence      REAL    NOT NULL DEFAULT 0.0,
    families        TEXT    NOT NULL DEFAULT '[]',
    log_count       INTEGER,
    countries       TEXT    NOT NULL DEFAULT '[]',
    data_types      TEXT    NOT NULL DEFAULT '[]',
    price_usd       TEXT    NOT NULL DEFAULT '',
    sender_name     TEXT    NOT NULL DEFAULT '',
    message_text    TEXT    NOT NULL DEFAULT '',
    has_download    INTEGER NOT NULL DEFAULT 0,
    download_type   TEXT    NOT NULL DEFAULT '',
    collected_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(message_rowid)
);
""")

# Add columns to existing stealer_logs table if they're missing
try:
    conn.execute("ALTER TABLE stealer_logs ADD COLUMN has_download INTEGER NOT NULL DEFAULT 0")
    print("  Added has_download column")
except Exception:
    pass  # already exists
try:
    conn.execute("ALTER TABLE stealer_logs ADD COLUMN download_type TEXT NOT NULL DEFAULT ''")
    print("  Added download_type column")
except Exception:
    pass  # already exists

# Settings table
conn.execute("""
CREATE TABLE IF NOT EXISTS scanner_settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL DEFAULT ''
)
""")
print("  Ensured scanner_settings table")

conn.commit()
conn.close()
print("Migration complete.")
