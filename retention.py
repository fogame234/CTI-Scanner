"""
Data retention and archival.

Periodically:
  1. Archives messages older than RETAIN_DAYS to compressed JSON files
  2. Purges archived messages from the database
  3. Purges old IOCs past RETAIN_IOCS_DAYS
  4. Purges old fired alerts past RETAIN_ALERTS_DAYS
  5. Sends a summary to ntfy

Archives are written to ARCHIVE_DIR as gzipped JSON, one file per run,
named by date: archive_2026-08-18T09-00-00.json.gz
"""

import gzip
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

import config
import notify

logger = logging.getLogger(__name__)


async def run_retention_sqlite():
    """Run the full retention cycle on the SQLite backend."""
    import db
    conn = await db._get()

    now = datetime.now(timezone.utc)
    msg_cutoff = (now - timedelta(days=config.RETAIN_DAYS)).isoformat()
    ioc_cutoff = (now - timedelta(days=config.RETAIN_IOCS_DAYS)).isoformat()
    alert_cutoff = (now - timedelta(days=config.RETAIN_ALERTS_DAYS)).isoformat()

    logger.info(
        "Retention run: messages older than %s, IOCs older than %s, alerts older than %s",
        msg_cutoff[:10], ioc_cutoff[:10], alert_cutoff[:10],
    )

    # ── 1. Archive old messages ───────────────────────────────────────
    rows = await conn.execute_fetchall(
        """SELECT m.*, c.title AS channel_title, c.username AS channel_username
           FROM messages m
           LEFT JOIN channels c ON m.channel_id = c.id
           WHERE m.date < ?
           ORDER BY m.date ASC""",
        (msg_cutoff,),
    )

    messages_archived = len(rows)
    archive_path = ""

    if rows:
        archive_data = {
            "archived_at": now.isoformat(),
            "cutoff_date": msg_cutoff,
            "message_count": len(rows),
            "messages": [dict(r) for r in rows],
        }

        archive_path = _write_archive(archive_data, now)
        logger.info("Archived %d messages to %s", len(rows), archive_path)

    # ── 2. Purge archived messages ────────────────────────────────────
    # Delete IOCs referencing these messages first (FK constraint)
    cursor = await conn.execute(
        "DELETE FROM extracted_iocs WHERE message_rowid IN "
        "(SELECT id FROM messages WHERE date < ?)",
        (msg_cutoff,),
    )
    iocs_from_messages = cursor.rowcount

    # Delete alerts referencing these messages
    await conn.execute(
        "DELETE FROM alerts_fired WHERE message_rowid IN "
        "(SELECT id FROM messages WHERE date < ?)",
        (msg_cutoff,),
    )

    cursor = await conn.execute(
        "DELETE FROM messages WHERE date < ?",
        (msg_cutoff,),
    )
    messages_purged = cursor.rowcount

    # ── 3. Purge standalone old IOCs (beyond message-linked ones) ─────
    cursor = await conn.execute(
        "DELETE FROM extracted_iocs WHERE first_seen < ?",
        (ioc_cutoff,),
    )
    iocs_purged = cursor.rowcount + iocs_from_messages

    # ── 4. Purge old alerts ───────────────────────────────────────────
    cursor = await conn.execute(
        "DELETE FROM alerts_fired WHERE fired_at < ?",
        (alert_cutoff,),
    )
    alerts_purged = cursor.rowcount

    # ── 4b. Purge old stealer log entries ─────────────────────────────
    await conn.execute(
        "DELETE FROM stealer_logs WHERE date < ?",
        (msg_cutoff,),
    )

    await conn.commit()

    # ── 5. Rebuild FTS index after bulk deletes ───────────────────────
    # The delete trigger handles individual rows, but after a bulk purge
    # it's safer to rebuild to avoid index drift.
    if messages_purged > 100:
        logger.info("Rebuilding FTS index after purging %d messages …", messages_purged)
        try:
            await conn.execute("INSERT INTO messages_fts(messages_fts) VALUES('rebuild')")
            await conn.commit()
        except Exception as e:
            logger.warning("FTS rebuild failed (non-fatal): %s", e)

    # ── 6. Reclaim disk space ─────────────────────────────────────────
    # VACUUM runs separately since it can't run inside a transaction
    if messages_purged > 0:
        try:
            await conn.execute("VACUUM")
        except Exception:
            pass  # non-fatal if locked

    logger.info(
        "Retention complete: archived=%d, purged=%d msgs / %d iocs / %d alerts",
        messages_archived, messages_purged, iocs_purged, alerts_purged,
    )

    # ── 7. Notify ─────────────────────────────────────────────────────
    if messages_archived > 0 or iocs_purged > 0 or alerts_purged > 0:
        await notify.send_retention_report(
            messages_archived=messages_archived,
            messages_purged=messages_purged,
            iocs_purged=iocs_purged,
            alerts_purged=alerts_purged,
            archive_path=archive_path,
        )

    return {
        "messages_archived": messages_archived,
        "messages_purged": messages_purged,
        "iocs_purged": iocs_purged,
        "alerts_purged": alerts_purged,
        "archive_path": archive_path,
    }


async def run_retention_elasticsearch():
    """Run retention on the Elasticsearch backend using delete_by_query."""
    from elasticsearch import AsyncElasticsearch
    from db_elastic import _get, IDX_MESSAGES, IDX_IOCS, IDX_ALERTS

    es = await _get()
    now = datetime.now(timezone.utc)
    msg_cutoff = (now - timedelta(days=config.RETAIN_DAYS)).isoformat()
    ioc_cutoff = (now - timedelta(days=config.RETAIN_IOCS_DAYS)).isoformat()
    alert_cutoff = (now - timedelta(days=config.RETAIN_ALERTS_DAYS)).isoformat()

    logger.info("ES retention: messages < %s, IOCs < %s, alerts < %s",
                msg_cutoff[:10], ioc_cutoff[:10], alert_cutoff[:10])

    # ── 1. Archive old messages to file ───────────────────────────────
    archive_path = ""
    messages_archived = 0

    try:
        resp = await es.search(
            index=IDX_MESSAGES,
            body={
                "query": {"range": {"date": {"lt": msg_cutoff}}},
                "size": 10000,
                "sort": [{"date": "asc"}],
            },
            scroll="5m",
        )
        scroll_id = resp.get("_scroll_id")
        all_docs = [h["_source"] for h in resp["hits"]["hits"]]

        while resp["hits"]["hits"]:
            resp = await es.scroll(scroll_id=scroll_id, scroll="5m")
            all_docs.extend(h["_source"] for h in resp["hits"]["hits"])

        if scroll_id:
            await es.clear_scroll(scroll_id=scroll_id)

        messages_archived = len(all_docs)
        if all_docs:
            archive_data = {
                "archived_at": now.isoformat(),
                "cutoff_date": msg_cutoff,
                "message_count": len(all_docs),
                "messages": all_docs,
            }
            archive_path = _write_archive(archive_data, now)
            logger.info("Archived %d messages to %s", len(all_docs), archive_path)
    except Exception as e:
        logger.error("ES archive scroll failed: %s", e)

    # ── 2. Purge ──────────────────────────────────────────────────────
    messages_purged = 0
    iocs_purged = 0
    alerts_purged = 0

    try:
        r = await es.delete_by_query(
            index=IDX_MESSAGES,
            body={"query": {"range": {"date": {"lt": msg_cutoff}}}},
            conflicts="proceed",
        )
        messages_purged = r.get("deleted", 0)
    except Exception as e:
        logger.error("ES message purge failed: %s", e)

    try:
        r = await es.delete_by_query(
            index=IDX_IOCS,
            body={"query": {"range": {"first_seen": {"lt": ioc_cutoff}}}},
            conflicts="proceed",
        )
        iocs_purged = r.get("deleted", 0)
    except Exception as e:
        logger.error("ES IOC purge failed: %s", e)

    try:
        r = await es.delete_by_query(
            index=IDX_ALERTS,
            body={"query": {"range": {"fired_at": {"lt": alert_cutoff}}}},
            conflicts="proceed",
        )
        alerts_purged = r.get("deleted", 0)
    except Exception as e:
        logger.error("ES alert purge failed: %s", e)

    logger.info("ES retention complete: archived=%d, purged=%d msgs / %d iocs / %d alerts",
                messages_archived, messages_purged, iocs_purged, alerts_purged)

    if messages_archived > 0 or iocs_purged > 0 or alerts_purged > 0:
        await notify.send_retention_report(
            messages_archived=messages_archived,
            messages_purged=messages_purged,
            iocs_purged=iocs_purged,
            alerts_purged=alerts_purged,
            archive_path=archive_path,
        )

    return {
        "messages_archived": messages_archived,
        "messages_purged": messages_purged,
        "iocs_purged": iocs_purged,
        "alerts_purged": alerts_purged,
        "archive_path": archive_path,
    }


# ══════════════════════════════════════════════════════════════════════
#  ROUTER
# ══════════════════════════════════════════════════════════════════════

async def run_retention() -> dict:
    """Run retention using whichever backend is configured."""
    if config.DB_BACKEND == "elasticsearch":
        return await run_retention_elasticsearch()
    else:
        return await run_retention_sqlite()


# ══════════════════════════════════════════════════════════════════════
#  ARCHIVE WRITER
# ══════════════════════════════════════════════════════════════════════

def _write_archive(data: dict, ts: datetime) -> str:
    """Write archive data to a gzipped JSON file. Returns the file path."""
    archive_dir = Path(config.ARCHIVE_DIR)
    archive_dir.mkdir(parents=True, exist_ok=True)

    filename = f"archive_{ts.strftime('%Y-%m-%dT%H-%M-%S')}.json.gz"
    path = archive_dir / filename

    with gzip.open(path, "wt", encoding="utf-8", compresslevel=6) as f:
        json.dump(data, f, ensure_ascii=False, default=str)

    size_mb = path.stat().st_size / (1024 * 1024)
    logger.info("Archive written: %s (%.1f MB)", path, size_mb)
    return str(path)
