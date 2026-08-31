"""
Elasticsearch persistence backend.

Same public interface as db.py (SQLite) so scanner.py, bot.py, and web.py
work unchanged — just set DB_BACKEND=elasticsearch in .env.

Indices:
  {prefix}-channels        – monitored Telegram channels
  {prefix}-messages        – every message from monitored channels
  {prefix}-iocs            – extracted IOCs linked to messages
  {prefix}-alert-keywords  – keyword / regex alert rules
  {prefix}-alerts          – fired alert log
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any

from elasticsearch import AsyncElasticsearch, NotFoundError, ConflictError

import config

logger = logging.getLogger(__name__)

_es: AsyncElasticsearch | None = None

# ── Index names ───────────────────────────────────────────────────────
def _idx(name: str) -> str:
    return f"{config.ES_PREFIX}-{name}"

IDX_CHANNELS = _idx("channels")
IDX_MESSAGES = _idx("messages")
IDX_IOCS     = _idx("iocs")
IDX_KEYWORDS = _idx("alert-keywords")
IDX_ALERTS   = _idx("alerts")
IDX_STEALER  = _idx("stealer-logs")


# ══════════════════════════════════════════════════════════════════════
#  CONNECTION & INDEX SETUP
# ══════════════════════════════════════════════════════════════════════

async def init() -> AsyncElasticsearch:
    global _es
    if _es is not None:
        return _es

    kwargs: dict[str, Any] = {"hosts": config.ES_HOSTS}

    if config.ES_API_KEY:
        kwargs["api_key"] = config.ES_API_KEY
    elif config.ES_USERNAME:
        kwargs["basic_auth"] = (config.ES_USERNAME, config.ES_PASSWORD)

    if config.ES_CA_CERTS:
        kwargs["ca_certs"] = config.ES_CA_CERTS

    if not config.ES_VERIFY:
        kwargs["verify_certs"] = False
        kwargs["ssl_show_warn"] = False

    _es = AsyncElasticsearch(**kwargs)

    info = await _es.info()
    logger.info(
        "Connected to Elasticsearch %s (%s)",
        info["version"]["number"], config.ES_HOSTS,
    )

    await _create_indices()

    # Seed default alert keywords
    for kw in config.DEFAULT_ALERT_KEYWORDS:
        await add_alert_keyword(kw)

    return _es


async def close():
    global _es
    if _es:
        await _es.close()
        _es = None


async def _get() -> AsyncElasticsearch:
    if _es is None:
        return await init()
    return _es


async def _create_indices():
    """Create indices with mappings if they don't exist."""
    es = await _get()

    indices = {
        IDX_CHANNELS: {
            "mappings": {
                "properties": {
                    "channel_id":    {"type": "long"},
                    "title":         {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "username":      {"type": "keyword"},
                    "channel_type":  {"type": "keyword"},
                    "about":         {"type": "text"},
                    "participants":  {"type": "integer"},
                    "is_monitored":  {"type": "boolean"},
                    "added_at":      {"type": "date"},
                    "last_scraped":  {"type": "date"},
                    "notes":         {"type": "text"},
                    "tags":          {"type": "keyword"},
                }
            }
        },
        IDX_MESSAGES: {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "analysis": {
                    "analyzer": {
                        "ioc_analyzer": {
                            "type": "custom",
                            "tokenizer": "uax_url_email",
                            "filter": ["lowercase"],
                        }
                    }
                }
            },
            "mappings": {
                "properties": {
                    "channel_id":    {"type": "long"},
                    "channel_title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "channel_username": {"type": "keyword"},
                    "message_id":    {"type": "long"},
                    "sender_id":     {"type": "long"},
                    "sender_name":   {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "date":          {"type": "date"},
                    "text":          {"type": "text", "analyzer": "ioc_analyzer",
                                      "fields": {"standard": {"type": "text"}}},
                    "has_media":     {"type": "boolean"},
                    "media_type":    {"type": "keyword"},
                    "reply_to":      {"type": "long"},
                    "forward_from":  {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "views":         {"type": "integer"},
                    "collected_at":  {"type": "date"},
                }
            }
        },
        IDX_IOCS: {
            "mappings": {
                "properties": {
                    "message_doc_id": {"type": "keyword"},
                    "channel_id":     {"type": "long"},
                    "channel_title":  {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "ioc_type":       {"type": "keyword"},
                    "value":          {"type": "keyword",
                                       "fields": {"search": {"type": "text"}}},
                    "first_seen":     {"type": "date"},
                    "message_text":   {"type": "text"},
                    "message_date":   {"type": "date"},
                }
            }
        },
        IDX_KEYWORDS: {
            "mappings": {
                "properties": {
                    "keyword":    {"type": "keyword"},
                    "is_regex":   {"type": "boolean"},
                    "enabled":    {"type": "boolean"},
                    "created_at": {"type": "date"},
                }
            }
        },
        IDX_ALERTS: {
            "mappings": {
                "properties": {
                    "keyword_id":   {"type": "keyword"},
                    "keyword":      {"type": "keyword"},
                    "message_doc_id": {"type": "keyword"},
                    "channel_id":   {"type": "long"},
                    "channel_title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "snippet":      {"type": "text"},
                    "fired_at":     {"type": "date"},
                    "acknowledged": {"type": "boolean"},
                }
            }
        },
        IDX_STEALER: {
            "mappings": {
                "properties": {
                    "message_doc_id": {"type": "keyword"},
                    "channel_id":     {"type": "long"},
                    "channel_title":  {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "date":           {"type": "date"},
                    "confidence":     {"type": "float"},
                    "families":       {"type": "keyword"},
                    "log_count":      {"type": "integer"},
                    "countries":      {"type": "keyword"},
                    "data_types":     {"type": "keyword"},
                    "price_usd":      {"type": "keyword"},
                    "sender_name":    {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "message_text":   {"type": "text"},
                    "collected_at":   {"type": "date"},
                }
            }
        },
    }

    for idx_name, body in indices.items():
        if not await es.indices.exists(index=idx_name):
            await es.indices.create(index=idx_name, body=body)
            logger.info("Created index: %s", idx_name)


# ══════════════════════════════════════════════════════════════════════
#  CHANNELS
# ══════════════════════════════════════════════════════════════════════

async def upsert_channel(
    channel_id: int, title: str, username: str = "",
    channel_type: str = "", about: str = "",
    participants: int = 0, tags: list[str] | None = None,
    notes: str = "",
) -> None:
    es = await _get()
    now = datetime.now(timezone.utc).isoformat()
    doc_id = str(channel_id)

    doc = {
        "channel_id": channel_id,
        "title": title,
        "username": username,
        "channel_type": channel_type,
        "about": about,
        "participants": participants,
        "is_monitored": True,
        "tags": tags or [],
        "notes": notes,
    }

    try:
        existing = await es.get(index=IDX_CHANNELS, id=doc_id)
        src = existing["_source"]
        # Preserve fields the caller didn't set
        if not tags:
            doc["tags"] = src.get("tags", [])
        if not notes:
            doc["notes"] = src.get("notes", "")
        doc["added_at"] = src.get("added_at", now)
        doc["last_scraped"] = src.get("last_scraped", "")
        doc["is_monitored"] = src.get("is_monitored", True)
    except NotFoundError:
        doc["added_at"] = now
        doc["last_scraped"] = ""

    await es.index(index=IDX_CHANNELS, id=doc_id, document=doc)


async def set_monitored(channel_id: int, monitored: bool) -> None:
    es = await _get()
    await es.update(
        index=IDX_CHANNELS, id=str(channel_id),
        body={"doc": {"is_monitored": monitored}},
    )


async def get_monitored_channels() -> list[dict]:
    es = await _get()
    resp = await es.search(
        index=IDX_CHANNELS,
        body={"query": {"term": {"is_monitored": True}}, "size": 200},
    )
    return [_hit_to_channel(h) for h in resp["hits"]["hits"]]


async def get_all_channels() -> list[dict]:
    es = await _get()
    resp = await es.search(
        index=IDX_CHANNELS,
        body={"query": {"match_all": {}}, "size": 500,
              "sort": [{"added_at": "desc"}]},
    )
    return [_hit_to_channel(h) for h in resp["hits"]["hits"]]


async def get_channel(channel_id: int) -> dict | None:
    es = await _get()
    try:
        resp = await es.get(index=IDX_CHANNELS, id=str(channel_id))
        return _hit_to_channel(resp)
    except NotFoundError:
        return None


async def update_last_scraped(channel_id: int, ts: str) -> None:
    es = await _get()
    try:
        await es.update(
            index=IDX_CHANNELS, id=str(channel_id),
            body={"doc": {"last_scraped": ts}},
        )
    except NotFoundError:
        pass


def _hit_to_channel(hit: dict) -> dict:
    src = hit["_source"] if "_source" in hit else hit.get("_source", hit)
    return {
        "id": src.get("channel_id", int(hit.get("_id", 0))),
        "title": src.get("title", ""),
        "username": src.get("username", ""),
        "channel_type": src.get("channel_type", ""),
        "about": src.get("about", ""),
        "participants": src.get("participants", 0),
        "is_monitored": src.get("is_monitored", True),
        "added_at": src.get("added_at", ""),
        "last_scraped": src.get("last_scraped", ""),
        "notes": src.get("notes", ""),
        "tags": src.get("tags", []),
    }


# ══════════════════════════════════════════════════════════════════════
#  MESSAGES
# ══════════════════════════════════════════════════════════════════════

async def store_message(
    channel_id: int, message_id: int, sender_id: int | None,
    sender_name: str, date: str, text: str,
    has_media: bool = False, media_type: str = "",
    reply_to: int | None = None, forward_from: str = "",
    views: int = 0, raw_json: dict | None = None,
) -> str | None:
    """
    Store a message. Returns ES doc ID, or None if duplicate.
    Uses channel_id:message_id as the doc ID for dedup.
    """
    es = await _get()
    doc_id = f"{channel_id}:{message_id}"
    now = datetime.now(timezone.utc).isoformat()

    # Resolve channel title for denormalization
    chan = await get_channel(channel_id)
    chan_title = chan["title"] if chan else ""
    chan_username = chan["username"] if chan else ""

    doc = {
        "channel_id": channel_id,
        "channel_title": chan_title,
        "channel_username": chan_username,
        "message_id": message_id,
        "sender_id": sender_id,
        "sender_name": sender_name,
        "date": date,
        "text": text,
        "has_media": has_media,
        "media_type": media_type,
        "reply_to": reply_to,
        "forward_from": forward_from,
        "views": views,
        "collected_at": now,
    }

    try:
        await es.index(
            index=IDX_MESSAGES, id=doc_id, document=doc,
            op_type="create",  # fail if exists (dedup)
        )
        return doc_id
    except ConflictError:
        return None  # duplicate


async def store_iocs(message_doc_id: str, channel_id: int,
                      iocs: list[tuple[str, str]]) -> int:
    """Store extracted IOCs. Returns count stored."""
    es = await _get()
    now = datetime.now(timezone.utc).isoformat()

    chan = await get_channel(channel_id)
    chan_title = chan["title"] if chan else ""

    # Get message text for context
    msg_text = ""
    msg_date = now
    try:
        msg = await es.get(index=IDX_MESSAGES, id=message_doc_id)
        msg_text = msg["_source"].get("text", "")
        msg_date = msg["_source"].get("date", now)
    except NotFoundError:
        pass

    count = 0
    for ioc_type, value in iocs:
        ioc_doc_id = f"{message_doc_id}:{ioc_type}:{value}"
        doc = {
            "message_doc_id": message_doc_id,
            "channel_id": channel_id,
            "channel_title": chan_title,
            "ioc_type": ioc_type,
            "value": value,
            "first_seen": now,
            "message_text": msg_text[:500],
            "message_date": msg_date,
        }
        try:
            await es.index(
                index=IDX_IOCS, id=ioc_doc_id, document=doc,
                op_type="create",
            )
            count += 1
        except Exception:
            pass  # duplicate
    return count


async def get_channel_messages(channel_id: int, limit: int = 100,
                                offset: int = 0) -> list[dict]:
    es = await _get()
    resp = await es.search(
        index=IDX_MESSAGES,
        body={
            "query": {"term": {"channel_id": channel_id}},
            "sort": [{"date": "desc"}],
            "size": limit, "from": offset,
        },
    )
    return [h["_source"] | {"id": h["_id"]} for h in resp["hits"]["hits"]]


async def get_message(doc_id: str) -> dict | None:
    es = await _get()
    try:
        resp = await es.get(index=IDX_MESSAGES, id=doc_id)
        return resp["_source"] | {"id": resp["_id"]}
    except NotFoundError:
        return None


# ══════════════════════════════════════════════════════════════════════
#  IOC QUERIES
# ══════════════════════════════════════════════════════════════════════

async def search_iocs(ioc_type: str | None = None, value: str | None = None,
                       channel_id: int | None = None, limit: int = 100) -> list[dict]:
    es = await _get()
    must = []
    if ioc_type:
        must.append({"term": {"ioc_type": ioc_type}})
    if value:
        must.append({
            "bool": {
                "should": [
                    {"term": {"value": value}},
                    {"wildcard": {"value": f"*{value}*"}},
                    {"match": {"value.search": value}},
                ],
                "minimum_should_match": 1,
            }
        })
    if channel_id is not None:
        must.append({"term": {"channel_id": channel_id}})

    body = {
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "sort": [{"first_seen": "desc"}],
        "size": limit,
    }
    resp = await es.search(index=IDX_IOCS, body=body)
    return [h["_source"] | {"id": h["_id"]} for h in resp["hits"]["hits"]]


async def get_ioc_summary() -> list[dict]:
    es = await _get()
    resp = await es.search(
        index=IDX_IOCS,
        body={
            "size": 0,
            "aggs": {
                "by_type": {
                    "terms": {"field": "ioc_type", "size": 30},
                    "aggs": {
                        "unique_values": {
                            "cardinality": {"field": "value"}
                        }
                    }
                }
            }
        },
    )
    buckets = resp["aggregations"]["by_type"]["buckets"]
    return [
        {
            "ioc_type": b["key"],
            "unique_count": b["unique_values"]["value"],
            "total": b["doc_count"],
        }
        for b in buckets
    ]


async def get_ioc_timeline(ioc_value: str) -> list[dict]:
    es = await _get()
    resp = await es.search(
        index=IDX_IOCS,
        body={
            "query": {"term": {"value": ioc_value}},
            "sort": [{"message_date": "desc"}],
            "size": 100,
        },
    )
    results = []
    for h in resp["hits"]["hits"]:
        s = h["_source"]
        results.append({
            "ioc_type": s.get("ioc_type"),
            "first_seen": s.get("first_seen"),
            "channel_title": s.get("channel_title", ""),
            "channel_username": "",
            "text": s.get("message_text", ""),
            "date": s.get("message_date", ""),
        })
    return results


# ══════════════════════════════════════════════════════════════════════
#  FULL-TEXT SEARCH
# ══════════════════════════════════════════════════════════════════════

async def search_messages(query: str, limit: int = 50) -> list[dict]:
    es = await _get()
    resp = await es.search(
        index=IDX_MESSAGES,
        body={
            "query": {
                "multi_match": {
                    "query": query,
                    "fields": ["text^3", "text.standard^2",
                               "sender_name", "channel_title",
                               "forward_from"],
                    "type": "best_fields",
                    "fuzziness": "AUTO",
                }
            },
            "highlight": {
                "fields": {
                    "text": {
                        "pre_tags": ["»"], "post_tags": ["«"],
                        "fragment_size": 150, "number_of_fragments": 1,
                    }
                }
            },
            "sort": ["_score", {"date": "desc"}],
            "size": limit,
        },
    )

    results = []
    for h in resp["hits"]["hits"]:
        s = h["_source"]
        highlight = h.get("highlight", {}).get("text", [""])[0]
        results.append({
            "id": h["_id"],
            "channel_id": s.get("channel_id"),
            "message_id": s.get("message_id"),
            "sender_name": s.get("sender_name", ""),
            "date": s.get("date", ""),
            "snippet": highlight or s.get("text", "")[:150],
            "channel_title": s.get("channel_title", ""),
            "channel_username": s.get("channel_username", ""),
            "rank": h.get("_score", 0),
        })
    return results


# ══════════════════════════════════════════════════════════════════════
#  ALERT KEYWORDS
# ══════════════════════════════════════════════════════════════════════

async def add_alert_keyword(keyword: str, is_regex: bool = False) -> str | None:
    es = await _get()
    kw = keyword.lower().strip()
    doc_id = f"kw:{kw}"
    now = datetime.now(timezone.utc).isoformat()

    try:
        await es.get(index=IDX_KEYWORDS, id=doc_id)
        return None  # already exists
    except NotFoundError:
        pass

    await es.index(
        index=IDX_KEYWORDS, id=doc_id,
        document={
            "keyword": kw,
            "is_regex": is_regex,
            "enabled": True,
            "created_at": now,
        },
    )
    return doc_id


async def remove_alert_keyword(keyword: str) -> bool:
    es = await _get()
    doc_id = f"kw:{keyword.lower().strip()}"
    try:
        await es.delete(index=IDX_KEYWORDS, id=doc_id)
        return True
    except NotFoundError:
        return False


async def get_alert_keywords() -> list[dict]:
    es = await _get()
    resp = await es.search(
        index=IDX_KEYWORDS,
        body={
            "query": {"term": {"enabled": True}},
            "size": 200,
        },
    )
    return [h["_source"] | {"id": h["_id"]} for h in resp["hits"]["hits"]]


async def fire_alert(keyword_id: str, message_doc_id: str,
                      channel_id: int, snippet: str) -> str:
    es = await _get()
    now = datetime.now(timezone.utc).isoformat()

    # Get keyword text
    kw_text = keyword_id
    try:
        kw_doc = await es.get(index=IDX_KEYWORDS, id=keyword_id)
        kw_text = kw_doc["_source"].get("keyword", keyword_id)
    except NotFoundError:
        pass

    chan = await get_channel(channel_id)
    chan_title = chan["title"] if chan else ""

    doc = {
        "keyword_id": keyword_id,
        "keyword": kw_text,
        "message_doc_id": message_doc_id,
        "channel_id": channel_id,
        "channel_title": chan_title,
        "snippet": snippet,
        "fired_at": now,
        "acknowledged": False,
    }

    resp = await es.index(index=IDX_ALERTS, document=doc)
    return resp["_id"]


async def get_recent_alerts(limit: int = 50, unack_only: bool = False) -> list[dict]:
    es = await _get()
    query: dict = {"match_all": {}}
    if unack_only:
        query = {"term": {"acknowledged": False}}

    resp = await es.search(
        index=IDX_ALERTS,
        body={
            "query": query,
            "sort": [{"fired_at": "desc"}],
            "size": limit,
        },
    )
    return [h["_source"] | {"id": h["_id"]} for h in resp["hits"]["hits"]]


async def acknowledge_alert(alert_id: str) -> None:
    es = await _get()
    await es.update(
        index=IDX_ALERTS, id=alert_id,
        body={"doc": {"acknowledged": True}},
    )


# ══════════════════════════════════════════════════════════════════════
#  STATS / EXPORT
# ══════════════════════════════════════════════════════════════════════

async def get_stats() -> dict:
    es = await _get()
    stats = {}

    for idx, key in [(IDX_CHANNELS, "channels"), (IDX_MESSAGES, "messages"),
                      (IDX_IOCS, "iocs"), (IDX_ALERTS, "alerts")]:
        try:
            resp = await es.count(index=idx)
            stats[key] = resp["count"]
        except Exception:
            stats[key] = 0

    # Monitored count
    try:
        resp = await es.count(
            index=IDX_CHANNELS,
            body={"query": {"term": {"is_monitored": True}}},
        )
        stats["monitored"] = resp["count"]
    except Exception:
        stats["monitored"] = 0

    # Unack alerts
    try:
        resp = await es.count(
            index=IDX_ALERTS,
            body={"query": {"term": {"acknowledged": False}}},
        )
        stats["unack_alerts"] = resp["count"]
    except Exception:
        stats["unack_alerts"] = 0

    return stats


async def export_all() -> dict:
    es = await _get()
    now = datetime.now(timezone.utc).isoformat()

    async def _scroll_all(index: str, size: int = 500) -> list[dict]:
        docs = []
        try:
            resp = await es.search(
                index=index,
                body={"query": {"match_all": {}}, "size": size},
                scroll="2m",
            )
            scroll_id = resp.get("_scroll_id")
            docs.extend([h["_source"] | {"_id": h["_id"]} for h in resp["hits"]["hits"]])

            while resp["hits"]["hits"]:
                resp = await es.scroll(scroll_id=scroll_id, scroll="2m")
                docs.extend([h["_source"] | {"_id": h["_id"]} for h in resp["hits"]["hits"]])

            if scroll_id:
                await es.clear_scroll(scroll_id=scroll_id)
        except Exception as e:
            logger.warning("Export scroll error for %s: %s", index, e)
        return docs

    return {
        "exported_at": now,
        "stats": await get_stats(),
        "channels": await _scroll_all(IDX_CHANNELS),
        "ioc_summary": await get_ioc_summary(),
        "recent_alerts": await get_recent_alerts(200),
    }


# ══════════════════════════════════════════════════════════════════════
#  ELASTICSEARCH-SPECIFIC QUERIES
#  (Bonus queries that take advantage of ES aggregations)
# ══════════════════════════════════════════════════════════════════════

async def ioc_top_values(ioc_type: str, limit: int = 20) -> list[dict]:
    """Top N most-seen IOC values of a given type."""
    es = await _get()
    resp = await es.search(
        index=IDX_IOCS,
        body={
            "size": 0,
            "query": {"term": {"ioc_type": ioc_type}},
            "aggs": {
                "top_values": {
                    "terms": {"field": "value", "size": limit},
                    "aggs": {
                        "channels": {
                            "cardinality": {"field": "channel_id"}
                        },
                        "latest": {
                            "max": {"field": "first_seen"}
                        }
                    }
                }
            }
        },
    )
    return [
        {
            "value": b["key"],
            "count": b["doc_count"],
            "channels": b["channels"]["value"],
            "latest": b["latest"]["value_as_string"],
        }
        for b in resp["aggregations"]["top_values"]["buckets"]
    ]


async def channel_message_volume(days: int = 30) -> list[dict]:
    """Message count per channel over the last N days."""
    es = await _get()
    resp = await es.search(
        index=IDX_MESSAGES,
        body={
            "size": 0,
            "query": {"range": {"date": {"gte": f"now-{days}d"}}},
            "aggs": {
                "by_channel": {
                    "terms": {"field": "channel_title.keyword", "size": 50},
                }
            }
        },
    )
    return [
        {"channel": b["key"], "messages": b["doc_count"]}
        for b in resp["aggregations"]["by_channel"]["buckets"]
    ]


async def ioc_co_occurrence(ioc_value: str) -> list[dict]:
    """Find other IOCs that appear in the same messages as the given IOC."""
    es = await _get()
    # Step 1: find all message_doc_ids containing this IOC
    resp = await es.search(
        index=IDX_IOCS,
        body={
            "query": {"term": {"value": ioc_value}},
            "size": 200,
            "_source": ["message_doc_id"],
        },
    )
    msg_ids = [h["_source"]["message_doc_id"] for h in resp["hits"]["hits"]]
    if not msg_ids:
        return []

    # Step 2: find all other IOCs in those messages
    resp2 = await es.search(
        index=IDX_IOCS,
        body={
            "size": 0,
            "query": {
                "bool": {
                    "must": [{"terms": {"message_doc_id": msg_ids}}],
                    "must_not": [{"term": {"value": ioc_value}}],
                }
            },
            "aggs": {
                "co_iocs": {
                    "terms": {"field": "value", "size": 20},
                    "aggs": {
                        "type": {"terms": {"field": "ioc_type", "size": 1}},
                    }
                }
            }
        },
    )
    return [
        {
            "value": b["key"],
            "ioc_type": b["type"]["buckets"][0]["key"] if b["type"]["buckets"] else "unknown",
            "co_occurrences": b["doc_count"],
        }
        for b in resp2["aggregations"]["co_iocs"]["buckets"]
    ]

# ══════════════════════════════════════════════════════════════════════
#  STEALER LOGS
# ══════════════════════════════════════════════════════════════════════

async def store_stealer_log(
    message_rowid: str, channel_id: int, channel_title: str,
    date: str, sender_name: str, message_text: str,
    confidence: float, families: list[str], log_count: int | None,
    countries: list[str], data_types: list[str], price_usd: str,
) -> str | None:
    es = await _get()
    now = datetime.now(timezone.utc).isoformat()
    doc_id = f"stealer:{message_rowid}"
    doc = {
        "message_doc_id": message_rowid,
        "channel_id": channel_id,
        "channel_title": channel_title,
        "date": date,
        "confidence": confidence,
        "families": families,
        "log_count": log_count,
        "countries": countries,
        "data_types": data_types,
        "price_usd": price_usd,
        "sender_name": sender_name,
        "message_text": message_text[:2000],
        "collected_at": now,
    }
    try:
        await es.index(index=IDX_STEALER, id=doc_id, document=doc, op_type="create")
        return doc_id
    except ConflictError:
        return None


async def get_stealer_logs(
    channel_id: int | None = None,
    family: str | None = None,
    limit: int = 100,
) -> list[dict]:
    es = await _get()
    must = []
    if channel_id is not None:
        must.append({"term": {"channel_id": channel_id}})
    if family:
        must.append({"term": {"families": family}})
    resp = await es.search(
        index=IDX_STEALER,
        body={
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"date": "desc"}],
            "size": limit,
        },
    )
    return [h["_source"] | {"id": h["_id"]} for h in resp["hits"]["hits"]]


async def get_stealer_log_stats() -> dict:
    es = await _get()
    resp = await es.search(
        index=IDX_STEALER,
        body={
            "size": 0,
            "aggs": {
                "by_family": {"terms": {"field": "families", "size": 20}},
                "by_channel": {"terms": {"field": "channel_title.keyword", "size": 20}},
                "total": {"value_count": {"field": "date"}},
            }
        },
    )
    aggs = resp["aggregations"]
    return {
        "total": aggs["total"]["value"],
        "by_family": {b["key"]: b["doc_count"] for b in aggs["by_family"]["buckets"]},
        "by_channel": {b["key"]: b["doc_count"] for b in aggs["by_channel"]["buckets"]},
    }
