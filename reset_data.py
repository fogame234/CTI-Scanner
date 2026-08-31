#!/usr/bin/env python3
"""
Reset the database while keeping monitored channels.

Purges: messages, IOCs, stealer logs, fired alerts, query log.
Keeps:  channels (with monitoring status), alert keywords.

Usage:
  python reset_data.py              # interactive confirmation
  python reset_data.py --yes        # skip confirmation
  python reset_data.py --everything # nuke channels and keywords too
"""

import argparse
import asyncio
import sys

import config


async def reset_sqlite(keep_channels: bool = True):
    import aiosqlite
    db = await aiosqlite.connect(config.DB_PATH)

    tables_to_purge = [
        "stealer_logs",
        "extracted_iocs",
        "alerts_fired",
        "messages",
    ]

    if not keep_channels:
        tables_to_purge.extend(["channels", "alert_keywords"])

    for table in tables_to_purge:
        await db.execute(f"DELETE FROM {table}")
        print(f"  Purged {table}")

    # Rebuild FTS
    try:
        await db.execute("INSERT INTO messages_fts(messages_fts) VALUES('rebuild')")
        print("  Rebuilt FTS index")
    except Exception:
        pass

    # Reset autoincrement counters
    await db.execute("DELETE FROM sqlite_sequence WHERE name IN (%s)" %
                     ",".join(f"'{t}'" for t in tables_to_purge))

    await db.commit()
    await db.close()

    # VACUUM must run outside a transaction, so use a fresh connection
    import sqlite3
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("VACUUM")
    conn.close()
    print("  Vacuumed database")


async def reset_elasticsearch(keep_channels: bool = True):
    from elasticsearch import AsyncElasticsearch
    from db_elastic import IDX_MESSAGES, IDX_IOCS, IDX_ALERTS, IDX_STEALER, IDX_CHANNELS, IDX_KEYWORDS

    kwargs = {"hosts": config.ES_HOSTS}
    if config.ES_API_KEY:
        kwargs["api_key"] = config.ES_API_KEY
    elif config.ES_USERNAME:
        kwargs["basic_auth"] = (config.ES_USERNAME, config.ES_PASSWORD)
    if not config.ES_VERIFY:
        kwargs["verify_certs"] = False
        kwargs["ssl_show_warn"] = False

    es = AsyncElasticsearch(**kwargs)

    indices_to_purge = [IDX_MESSAGES, IDX_IOCS, IDX_ALERTS, IDX_STEALER]
    if not keep_channels:
        indices_to_purge.extend([IDX_CHANNELS, IDX_KEYWORDS])

    for idx in indices_to_purge:
        try:
            r = await es.delete_by_query(
                index=idx,
                body={"query": {"match_all": {}}},
                conflicts="proceed",
            )
            print(f"  Purged {idx}: {r.get('deleted', 0)} docs")
        except Exception as e:
            print(f"  {idx}: {e}")

    await es.close()


async def run(keep_channels: bool):
    if config.DB_BACKEND == "elasticsearch":
        await reset_elasticsearch(keep_channels)
    else:
        await reset_sqlite(keep_channels)


def main():
    parser = argparse.ArgumentParser(description="Reset CTI scanner database")
    parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation")
    parser.add_argument("--everything", action="store_true",
                        help="Also remove channels and alert keywords")
    args = parser.parse_args()

    keep = not args.everything

    print()
    if keep:
        print("This will DELETE all collected data:")
        print("  - Messages")
        print("  - Extracted IOCs")
        print("  - Stealer log entries")
        print("  - Fired alerts")
        print()
        print("This will KEEP:")
        print("  - Monitored channels")
        print("  - Alert keywords")
    else:
        print("This will DELETE EVERYTHING including channels and keywords.")

    print()

    if not args.yes:
        confirm = input("Type 'reset' to confirm: ")
        if confirm.strip().lower() != "reset":
            print("Aborted.")
            sys.exit(0)

    print()
    print(f"Resetting ({config.DB_BACKEND}) …")
    asyncio.run(run(keep))
    print()
    print("Done. Restart the scanner to continue collecting.")


if __name__ == "__main__":
    main()
