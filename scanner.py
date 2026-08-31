"""
Core Telegram scanner using Telethon (client API).

Capabilities:
  • Search public channels/groups by keyword
  • Join and monitor channels in real time
  • Backfill message history on first join
  • Extract IOCs from every message
  • Fire alerts when keyword matches are found
  • Forward alerts to a notification chat
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timezone

from telethon import TelegramClient, events, functions, types
from telethon.tl.functions.channels import JoinChannelRequest, GetFullChannelRequest
from telethon.tl.functions.contacts import SearchRequest
from telethon.tl.functions.messages import SearchGlobalRequest, ImportChatInviteRequest, CheckChatInviteRequest
from telethon.errors import (
    ChannelPrivateError,
    ChatAdminRequiredError,
    FloodWaitError,
    UserAlreadyParticipantError,
    InviteHashExpiredError,
)

import config
import db_router as db
import notify
from health import get_tracker
from utils.extractor import extract
from utils.stealer_parser import parse as parse_stealer_log
import filters as f

logger = logging.getLogger(__name__)


class CTIScanner:
    def __init__(self):
        self.client = TelegramClient(
            config.SESSION, config.API_ID, config.API_HASH
        )
        self._alert_keywords: list[dict] = []
        self._notify_chat: int | None = None  # chat ID to forward alerts to
        self._health = get_tracker()

    # ── Lifecycle ─────────────────────────────────────────────────────

    async def start(self):
        await self.client.start(phone=config.PHONE)
        me = await self.client.get_me()
        logger.info("Scanner logged in as %s (id=%d)", me.first_name, me.id)
        self._health.set_connected(True)
        await db.init()
        await f.seed_defaults()
        await notify.seed_ntfy_from_env()
        await self._reload_keywords()
        self._register_handlers()
        logger.info("Real-time message handler registered.")

    async def run_forever(self):
        """Start scanner + periodic backfill + retention + health + discovery loops."""
        await self.start()
        logger.info("Scanner running. Monitoring channels in real time.")
        asyncio.create_task(self._backfill_loop())
        asyncio.create_task(self._retention_loop())
        asyncio.create_task(self._health_loop())
        asyncio.create_task(self._discovery_loop())
        await self.client.run_until_disconnected()

    async def stop(self):
        self._health.set_connected(False)
        await self.client.disconnect()
        await notify.close()
        await db.close()

    # ── Channel discovery ─────────────────────────────────────────────

    async def search_channels(self, query: str, limit: int = 20) -> list[dict]:
        """
        Search Telegram for public channels/groups matching a keyword.
        Returns list of dicts with channel metadata.
        """
        results = []
        try:
            # contacts.search finds public channels and bots
            search_result = await self.client(SearchRequest(
                q=query, limit=limit
            ))

            for chat in search_result.chats:
                if isinstance(chat, (types.Channel, types.Chat)):
                    ctype = "channel"
                    if getattr(chat, "megagroup", False):
                        ctype = "megagroup"
                    elif isinstance(chat, types.Chat):
                        ctype = "group"

                    results.append({
                        "id": chat.id,
                        "title": getattr(chat, "title", ""),
                        "username": getattr(chat, "username", "") or "",
                        "type": ctype,
                        "participants": getattr(chat, "participants_count", 0) or 0,
                        "about": "",
                    })
        except FloodWaitError as e:
            logger.warning("FloodWait on search: %ds", e.seconds)
            await asyncio.sleep(e.seconds)
        except Exception as e:
            logger.error("Search error: %s", e)

        # Also try global message search for channels discussing the topic
        try:
            global_result = await self.client(SearchGlobalRequest(
                q=query,
                filter=types.InputMessagesFilterEmpty(),
                min_date=None,
                max_date=None,
                offset_rate=0,
                offset_peer=types.InputPeerEmpty(),
                offset_id=0,
                limit=limit,
            ))
            seen_ids = {r["id"] for r in results}
            for chat in global_result.chats:
                if isinstance(chat, types.Channel) and chat.id not in seen_ids:
                    ctype = "megagroup" if chat.megagroup else "channel"
                    results.append({
                        "id": chat.id,
                        "title": chat.title,
                        "username": getattr(chat, "username", "") or "",
                        "type": ctype,
                        "participants": getattr(chat, "participants_count", 0) or 0,
                        "about": "",
                    })
                    seen_ids.add(chat.id)
        except Exception as e:
            logger.debug("Global search fallback error: %s", e)

        return results[:limit]

    async def resolve_channel(self, identifier: str) -> dict | None:
        """
        Resolve a channel by @username, t.me link, invite link, or numeric ID.
        Returns channel metadata dict or None.
        """
        identifier = identifier.strip()

        # Extract invite hash from private links
        invite_hash = None
        for prefix in ("https://t.me/+", "http://t.me/+", "t.me/+",
                        "https://t.me/joinchat/", "http://t.me/joinchat/",
                        "t.me/joinchat/"):
            if identifier.startswith(prefix):
                invite_hash = identifier[len(prefix):]
                break

        # If it's just a bare +hash
        if not invite_hash and identifier.startswith("+"):
            invite_hash = identifier[1:]

        # Handle private invite links
        if invite_hash:
            try:
                result = await self.client(CheckChatInviteRequest(invite_hash))
                # result can be ChatInvite (not joined) or ChatInviteAlready (already in)
                if isinstance(result, types.ChatInviteAlready):
                    chat = result.chat
                elif isinstance(result, types.ChatInvitePeek):
                    chat = result.chat
                elif isinstance(result, types.ChatInvite):
                    # Not joined yet — return what we know
                    return {
                        "id": None,  # unknown until we join
                        "title": result.title or "Unknown",
                        "username": "",
                        "type": "channel" if result.broadcast else "megagroup" if result.megagroup else "group",
                        "about": getattr(result, "about", "") or "",
                        "participants": result.participants_count or 0,
                        "_invite_hash": invite_hash,
                    }
                else:
                    return None

                return self._entity_to_dict(chat)
            except InviteHashExpiredError:
                logger.warning("Invite link expired: %s", invite_hash)
                return None
            except Exception as e:
                logger.warning("Could not check invite '%s': %s", invite_hash, e)
                return None

        # Strip t.me links and @ for public channels
        for prefix in ("https://t.me/", "http://t.me/", "t.me/", "@"):
            if identifier.startswith(prefix):
                identifier = identifier[len(prefix):]
                break

        try:
            entity = await self.client.get_entity(identifier)
        except Exception as e:
            logger.warning("Could not resolve '%s': %s", identifier, e)
            return None

        if isinstance(entity, (types.Channel, types.Chat)):
            return self._entity_to_dict(entity)
        return None

    def _entity_to_dict(self, entity) -> dict:
        """Convert a Telethon entity to our standard dict format."""
        about = ""
        participants = getattr(entity, "participants_count", 0) or 0

        ctype = "channel"
        if getattr(entity, "megagroup", False):
            ctype = "megagroup"
        elif isinstance(entity, types.Chat):
            ctype = "group"

        return {
            "id": entity.id,
            "title": getattr(entity, "title", ""),
            "username": getattr(entity, "username", "") or "",
            "type": ctype,
            "about": about,
            "participants": participants,
        }

    # ── Join & monitor ────────────────────────────────────────────────

    async def join_and_monitor(self, channel_id_or_username: str | int,
                                tags: list[str] | None = None,
                                notes: str = "") -> dict | None:
        """
        Join a channel (if not already joined), store it in DB as monitored,
        and kick off a history backfill.
        """
        if isinstance(channel_id_or_username, str):
            info = await self.resolve_channel(channel_id_or_username)
        else:
            info = await self.resolve_channel(str(channel_id_or_username))

        if not info:
            return None

        invite_hash = info.get("_invite_hash")

        # Try to join
        if invite_hash and info.get("id") is None:
            # Private invite link — need to import
            try:
                updates = await self.client(ImportChatInviteRequest(invite_hash))
                chat = updates.chats[0] if updates.chats else None
                if chat:
                    info["id"] = chat.id
                    info["title"] = getattr(chat, "title", info.get("title", ""))
                    info["username"] = getattr(chat, "username", "") or ""
                    logger.info("Joined via invite: %s (%d)", info["title"], info["id"])
            except UserAlreadyParticipantError:
                # Already in — need to find the channel by checking dialogs
                logger.info("Already in channel via invite link")
                # Try to find it in recent dialogs
                async for dialog in self.client.iter_dialogs(limit=50):
                    if dialog.title == info.get("title"):
                        info["id"] = dialog.entity.id
                        info["username"] = getattr(dialog.entity, "username", "") or ""
                        break
                if info.get("id") is None:
                    logger.warning("Could not find channel after invite join")
                    return None
            except InviteHashExpiredError:
                logger.warning("Invite link expired")
                return None
            except Exception as e:
                logger.error("Invite join error: %s", e)
                return None
        elif info.get("id"):
            # Public channel or already resolved — join normally
            try:
                entity = await self.client.get_entity(info["id"])
                await self.client(JoinChannelRequest(entity))
                logger.info("Joined channel: %s (%d)", info["title"], info["id"])
            except UserAlreadyParticipantError:
                logger.info("Already in channel: %s", info["title"])
            except (ChannelPrivateError, ChatAdminRequiredError) as e:
                logger.warning("Cannot join %s: %s", info["title"], e)
            except Exception as e:
                logger.error("Join error for %s: %s", info["title"], e)

        if not info.get("id"):
            return None

        # Store in DB
        await db.upsert_channel(
            channel_id=info["id"],
            title=info["title"],
            username=info["username"],
            channel_type=info["type"],
            about=info["about"],
            participants=info["participants"],
            tags=tags,
            notes=notes,
        )

        # Kick off backfill in background
        asyncio.create_task(self._backfill_channel(info["id"]))

        return info

    async def unmonitor(self, channel_id: int) -> bool:
        """Stop monitoring a channel (does not leave it)."""
        await db.set_monitored(channel_id, False)
        logger.info("Stopped monitoring channel %d", channel_id)
        return True

    # ── Real-time message handler ─────────────────────────────────────

    def _register_handlers(self):
        @self.client.on(events.NewMessage)
        async def on_new_message(event):
            # Only process messages from monitored channels
            chat = await event.get_chat()
            if not isinstance(chat, (types.Channel, types.Chat)):
                return

            channel_id = chat.id
            chan = await db.get_channel(channel_id)
            if not chan or not chan.get("is_monitored"):
                return

            await self._process_message(event.message, channel_id)

    async def _process_message(self, msg, channel_id: int) -> int | str | None:
        """Process and store a single message. Returns row/doc ID."""
        text = msg.message or ""
        if not text.strip() and not msg.media:
            return None

        sender_name = ""
        sender_id = None
        if msg.sender:
            sender_id = msg.sender.id
            sender_name = getattr(msg.sender, "first_name", "") or \
                          getattr(msg.sender, "title", "") or ""

        media_type = ""
        has_media = msg.media is not None
        if has_media:
            media_type = type(msg.media).__name__.replace("MessageMedia", "").lower()

        forward_from = ""
        if msg.forward:
            fwd_chat = getattr(msg.forward, "chat", None)
            if fwd_chat:
                forward_from = getattr(fwd_chat, "title", "") or \
                               getattr(fwd_chat, "username", "") or ""

        date_str = msg.date.isoformat() if msg.date else datetime.now(timezone.utc).isoformat()

        # ── Filter: skip spam/junk messages ───────────────────────────
        if not f.should_store_message(text):
            return None

        # ── Analyze content BEFORE storing ────────────────────────────
        has_iocs = False
        has_keyword = False
        is_stealer = False
        filtered_iocs = []
        stealer = None

        if text.strip():
            # Extract IOCs
            extracted = extract(text)
            if extracted.total > 0:
                filtered_iocs = f.filter_iocs(extracted.all_iocs())
                has_iocs = len(filtered_iocs) > 0

            # Check stealer log
            stealer = parse_stealer_log(text)
            is_stealer = stealer.is_stealer_log and \
                         f.should_store_stealer_log(stealer.confidence, stealer.has_download)

            # Check keywords
            text_lower = text.lower()
            for kw in self._alert_keywords:
                if kw.get("is_regex"):
                    try:
                        if re.search(kw["keyword"], text, re.IGNORECASE):
                            has_keyword = True
                            break
                    except re.error:
                        pass
                else:
                    if kw["keyword"] in text_lower:
                        has_keyword = True
                        break

        # ── Relevance filter: skip messages with no intel value ───────
        if not f.should_store_after_extraction(has_iocs, has_keyword, is_stealer):
            return None

        # ── Store the message ─────────────────────────────────────────
        row_id = await db.store_message(
            channel_id=channel_id,
            message_id=msg.id,
            sender_id=sender_id,
            sender_name=sender_name,
            date=date_str,
            text=text,
            has_media=has_media,
            media_type=media_type,
            reply_to=getattr(msg.reply_to, "reply_to_msg_id", None) if msg.reply_to else None,
            forward_from=forward_from,
            views=msg.views or 0,
        )

        if row_id is None:
            return None  # duplicate

        self._health.record_message()

        # ── Store extracted data ──────────────────────────────────────
        if filtered_iocs:
            await db.store_iocs(row_id, channel_id, filtered_iocs)
            logger.debug(
                "Stored %d IOCs from msg %d in channel %d",
                len(filtered_iocs), msg.id, channel_id,
            )

        if is_stealer and stealer:
            chan = await db.get_channel(channel_id)
            chan_title = chan["title"] if chan else ""
            await db.store_stealer_log(
                message_rowid=row_id,
                channel_id=channel_id,
                channel_title=chan_title,
                date=date_str,
                sender_name=sender_name,
                message_text=text,
                confidence=stealer.confidence,
                families=stealer.families,
                log_count=stealer.log_count,
                countries=stealer.countries,
                data_types=stealer.data_types,
                price_usd=stealer.price_usd,
                has_download=stealer.has_download,
                download_type=stealer.download_type,
            )
            logger.info(
                "Stealer log detected (%.0f%%) in channel %d: %s",
                stealer.confidence * 100, channel_id,
                ", ".join(stealer.families) or "unknown family",
            )

        # ── Fire alerts ───────────────────────────────────────────────
        if text.strip():
            await self._check_alerts(text, row_id, channel_id)

        return row_id

    # ── Alerting ──────────────────────────────────────────────────────

    async def _reload_keywords(self):
        self._alert_keywords = await db.get_alert_keywords()

    async def _check_alerts(self, text: str, message_rowid: int | str, channel_id: int):
        text_lower = text.lower()
        for kw in self._alert_keywords:
            matched = False
            if kw["is_regex"]:
                try:
                    matched = bool(re.search(kw["keyword"], text, re.IGNORECASE))
                except re.error:
                    pass
            else:
                matched = kw["keyword"] in text_lower

            if matched:
                snippet = text[:200]
                await db.fire_alert(kw["id"], message_rowid, channel_id, snippet)

                chan = await db.get_channel(channel_id)
                chan_title = chan["title"] if chan else str(channel_id)

                logger.info(
                    "🚨 ALERT [%s] fired in %s: %s",
                    kw["keyword"], chan_title, snippet[:80],
                )

                # Push to ntfy
                await notify.send_alert(
                    keyword=kw["keyword"],
                    channel_title=chan_title,
                    snippet=snippet,
                    channel_id=channel_id,
                )

                # Optionally forward to Telegram notification chat
                if self._notify_chat:
                    try:
                        await self.client.send_message(
                            self._notify_chat,
                            f"🚨 **Alert: `{kw['keyword']}`**\n"
                            f"📡 Channel: {chan_title}\n"
                            f"```\n{snippet}\n```",
                        )
                    except Exception as e:
                        logger.warning("Could not forward alert: %s", e)

    def set_notify_chat(self, chat_id: int):
        """Set the chat where alerts are forwarded."""
        self._notify_chat = chat_id

    async def add_keyword(self, keyword: str, is_regex: bool = False) -> bool:
        result = await db.add_alert_keyword(keyword, is_regex)
        await self._reload_keywords()
        return result is not None

    async def remove_keyword(self, keyword: str) -> bool:
        result = await db.remove_alert_keyword(keyword)
        await self._reload_keywords()
        return result

    # ── Backfill ──────────────────────────────────────────────────────

    async def _backfill_channel(self, channel_id: int):
        """Pull message history for a channel."""
        logger.info("Starting backfill for channel %d …", channel_id)
        try:
            entity = await self.client.get_entity(channel_id)
        except Exception as e:
            logger.error("Could not get entity for backfill (%d): %s", channel_id, e)
            return

        count = 0
        try:
            async for msg in self.client.iter_messages(
                entity, limit=config.BACKFILL_LIMIT
            ):
                result = await self._process_message(msg, channel_id)
                if result:
                    count += 1
                    if count % 100 == 0:
                        logger.info("  … backfilled %d messages for channel %d", count, channel_id)
                        await asyncio.sleep(0.5)  # gentle on rate limits
        except FloodWaitError as e:
            logger.warning("FloodWait during backfill: %ds", e.seconds)
            await asyncio.sleep(e.seconds)
        except Exception as e:
            logger.error("Backfill error for %d: %s", channel_id, e)

        now = datetime.now(timezone.utc).isoformat()
        await db.update_last_scraped(channel_id, now)
        logger.info("Backfill complete for channel %d: %d new messages", channel_id, count)

    async def _backfill_loop(self):
        """Periodically re-scrape monitored channels."""
        while True:
            await asyncio.sleep(config.BACKFILL_INTERVAL)
            channels = await db.get_monitored_channels()
            for chan in channels:
                logger.info("Periodic backfill: %s (%d)", chan["title"], chan["id"])
                await self._backfill_channel(chan["id"])
                await asyncio.sleep(5)  # breathing room between channels

    async def _retention_loop(self):
        """Periodically archive and purge old data."""
        # Wait a bit on startup so we don't run retention immediately
        await asyncio.sleep(60)
        while True:
            try:
                from retention import run_retention
                result = await run_retention()
                logger.info("Retention run result: %s", result)
            except Exception as e:
                logger.error("Retention run failed: %s", e)
            await asyncio.sleep(config.RETENTION_INTERVAL)

    async def _health_loop(self):
        """Periodic health check — runs every 60s, sends ntfy on state changes."""
        while True:
            await asyncio.sleep(60)
            self._health.set_connected(self.client.is_connected())
            await self._health.periodic_check()

    async def _discovery_loop(self):
        """Periodically search for new channels and add them as candidates."""
        if not config.DISCOVERY_KEYWORDS:
            logger.info("No DISCOVERY_KEYWORDS configured — auto-discovery disabled.")
            return

        # Wait on startup to let everything settle
        await asyncio.sleep(120)
        logger.info(
            "Auto-discovery enabled: %d keywords, every %ds",
            len(config.DISCOVERY_KEYWORDS), config.DISCOVERY_INTERVAL,
        )

        while True:
            new_count = 0
            for keyword in config.DISCOVERY_KEYWORDS:
                try:
                    results = await self.search_channels(keyword, limit=15)
                    for r in results:
                        cid = r.get("id")
                        if not cid:
                            continue

                        # Skip if below member threshold
                        if (r.get("participants") or 0) < config.DISCOVERY_MIN_MEMBERS:
                            continue

                        # Skip if already monitored or already a candidate
                        if await db.is_known_channel(cid):
                            continue

                        added = await db.add_candidate(
                            channel_id=cid,
                            title=r.get("title", ""),
                            username=r.get("username", ""),
                            channel_type=r.get("type", ""),
                            about=r.get("about", ""),
                            participants=r.get("participants", 0),
                            search_term=keyword,
                        )
                        if added:
                            new_count += 1
                            logger.info(
                                "Discovery: new candidate '%s' (%d) from '%s'",
                                r.get("title", ""), cid, keyword,
                            )

                    # Rate limit between searches
                    await asyncio.sleep(10)

                except FloodWaitError as e:
                    logger.warning("Discovery FloodWait: %ds", e.seconds)
                    await asyncio.sleep(e.seconds)
                except Exception as e:
                    logger.error("Discovery error for '%s': %s", keyword, e)

            if new_count > 0:
                await notify.send_discovery_alert(new_count)
                logger.info("Discovery complete: %d new candidates", new_count)
            else:
                logger.info("Discovery complete: no new candidates")

            await asyncio.sleep(config.DISCOVERY_INTERVAL)

    # ── Convenience queries ───────────────────────────────────────────

    async def search_messages(self, query: str, limit: int = 50) -> list[dict]:
        return await db.search_messages(query, limit)

    async def search_iocs(self, ioc_type: str | None = None,
                           value: str | None = None) -> list[dict]:
        return await db.search_iocs(ioc_type, value)

    async def get_stats(self) -> dict:
        return await db.get_stats()
