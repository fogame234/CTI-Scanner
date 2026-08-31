#!/usr/bin/env python3
"""
Companion Telegram Bot — command interface for the scanner.

Runs alongside the Telethon scanner client and provides a standard
bot interface so you can issue /scan, /monitor, /search, /alerts
commands from any Telegram chat.

This is optional. The scanner runs fine without it.
"""

import asyncio
import json
import logging
from html import escape as esc

from telegram import Update, BotCommand
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)
from telegram.constants import ParseMode

import config
import db_router as db

logger = logging.getLogger(__name__)

MAX_MSG = 4000
_scanner = None  # set by main.py


def set_scanner(scanner):
    global _scanner
    _scanner = scanner


async def _send(update: Update, text: str):
    if len(text) <= MAX_MSG:
        await update.message.reply_text(text, parse_mode=ParseMode.HTML,
                                        disable_web_page_preview=True)
        return
    chunks, buf = [], ""
    for line in text.split("\n"):
        if len(buf) + len(line) + 1 > MAX_MSG:
            chunks.append(buf)
            buf = line
        else:
            buf = buf + "\n" + line if buf else line
    if buf:
        chunks.append(buf)
    for chunk in chunks:
        await update.message.reply_text(chunk, parse_mode=ParseMode.HTML,
                                        disable_web_page_preview=True)
        await asyncio.sleep(0.3)


def _args(ctx: ContextTypes.DEFAULT_TYPE) -> str:
    return " ".join(ctx.args) if ctx.args else ""


# ══════════════════════════════════════════════════════════════════════
#  COMMANDS
# ══════════════════════════════════════════════════════════════════════

async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await _send(update, """🛡️ <b>CTI Telegram Scanner</b>

<b>Channel Discovery</b>
/scan &lt;keyword&gt; – Search for Telegram channels
/resolve &lt;@user or link&gt; – Get channel info

<b>Monitoring</b>
/monitor &lt;@channel or link&gt; – Join &amp; start monitoring
/unmonitor &lt;channel_id&gt; – Stop monitoring
/channels – List monitored channels
/backfill &lt;channel_id&gt; – Force re-scrape history

<b>Search &amp; Intel</b>
/search &lt;query&gt; – Full-text search all messages
/iocs [type] – List extracted IOCs
/ioc &lt;value&gt; – Look up a specific IOC across channels
/timeline &lt;ioc_value&gt; – Sightings of an IOC over time

<b>Alerts</b>
/alert add &lt;keyword&gt; – Add alert keyword
/alert add_regex &lt;pattern&gt; – Add regex alert
/alert remove &lt;keyword&gt; – Remove keyword
/alert list – List active keywords
/alerts – Show recent triggered alerts

<b>Utility</b>
/stats – Dashboard numbers
/export – Full JSON data export
/help – This message""")


async def cmd_scan(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = _args(ctx)
    if not query:
        await _send(update, "Usage: <code>/scan &lt;keyword&gt;</code>\n"
                            "Example: <code>/scan ransomware</code>")
        return

    await update.message.reply_text(f"🔎 Searching for <i>{esc(query)}</i> …",
                                    parse_mode=ParseMode.HTML)

    results = await _scanner.search_channels(query)
    if not results:
        await _send(update, f"❌ No channels found for <i>{esc(query)}</i>.")
        return

    lines = [f"📡 <b>Found {len(results)} channel(s) for \"{esc(query)}\"</b>", ""]
    for r in results:
        handle = f"@{r['username']}" if r["username"] else f"ID:{r['id']}"
        lines.append(
            f"• <b>{esc(r['title'])}</b> ({esc(handle)})\n"
            f"  Type: {r['type']} · Members: {r['participants']}\n"
            f"  → <code>/monitor {r['username'] or r['id']}</code>"
        )
        lines.append("")
    await _send(update, "\n".join(lines))


async def cmd_resolve(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    target = _args(ctx)
    if not target:
        await _send(update, "Usage: <code>/resolve @channel</code> or <code>/resolve https://t.me/xyz</code>")
        return

    info = await _scanner.resolve_channel(target)
    if not info:
        await _send(update, f"❌ Could not resolve <code>{esc(target)}</code>.")
        return

    lines = [
        f"📡 <b>{esc(info['title'])}</b>",
        f"🆔 ID: <code>{info['id']}</code>",
        f"👤 Username: @{esc(info['username'])}" if info["username"] else "👤 Private channel",
        f"📋 Type: {info['type']}",
        f"👥 Members: {info['participants']}",
    ]
    if info["about"]:
        lines.append(f"\n📝 {esc(info['about'][:500])}")
    lines.append(f"\n→ <code>/monitor {info['username'] or info['id']}</code>")
    await _send(update, "\n".join(lines))


async def cmd_monitor(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    target = _args(ctx)
    if not target:
        await _send(update, "Usage: <code>/monitor @channel</code> or <code>/monitor https://t.me/xyz</code>")
        return

    await update.message.reply_text(f"📡 Joining and setting up monitor for <i>{esc(target)}</i> …",
                                    parse_mode=ParseMode.HTML)

    info = await _scanner.join_and_monitor(target)
    if not info:
        await _send(update, f"❌ Could not join <code>{esc(target)}</code>.")
        return

    await _send(update,
        f"✅ <b>Now monitoring: {esc(info['title'])}</b>\n"
        f"🆔 {info['id']} · @{esc(info['username'])}\n"
        f"📥 Backfilling up to {config.BACKFILL_LIMIT} messages …\n"
        f"🔔 Messages will be scanned for IOCs and alert keywords."
    )


async def cmd_unmonitor(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    target = _args(ctx)
    if not target:
        await _send(update, "Usage: <code>/unmonitor &lt;channel_id&gt;</code>")
        return
    try:
        cid = int(target)
    except ValueError:
        await _send(update, "Provide the numeric channel ID.")
        return
    await _scanner.unmonitor(cid)
    await _send(update, f"✅ Stopped monitoring channel <code>{cid}</code>.")


async def cmd_channels(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    channels = await db.get_all_channels()
    if not channels:
        await _send(update, "No channels tracked yet. Use /scan to find channels.")
        return

    lines = [f"📡 <b>Tracked Channels ({len(channels)})</b>", ""]
    for c in channels:
        status = "🟢" if c["is_monitored"] else "⚫"
        handle = f"@{c['username']}" if c["username"] else ""
        lines.append(
            f"{status} <b>{esc(c['title'])}</b> {esc(handle)}\n"
            f"   ID: <code>{c['id']}</code> · {c['channel_type']} · "
            f"Members: {c['participants']}\n"
            f"   Last scraped: {esc(c['last_scraped'][:16]) if c['last_scraped'] else 'never'}"
        )
        lines.append("")
    await _send(update, "\n".join(lines))


async def cmd_backfill(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    target = _args(ctx)
    if not target:
        await _send(update, "Usage: <code>/backfill &lt;channel_id&gt;</code>")
        return
    try:
        cid = int(target)
    except ValueError:
        await _send(update, "Provide the numeric channel ID.")
        return
    await update.message.reply_text("📥 Starting backfill …")
    await _scanner._backfill_channel(cid)
    await _send(update, f"✅ Backfill complete for <code>{cid}</code>.")


# ── Search & IOCs ─────────────────────────────────────────────────────

async def cmd_search(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = _args(ctx)
    if not query:
        await _send(update, "Usage: <code>/search &lt;keyword&gt;</code>")
        return

    results = await db.search_messages(query, limit=20)
    if not results:
        await _send(update, f"❌ No messages matching <i>{esc(query)}</i>.")
        return

    lines = [f"🔍 <b>{len(results)} result(s) for \"{esc(query)}\"</b>", ""]
    for r in results:
        snippet = (r.get("snippet") or "")[:200]
        snippet = snippet.replace("»", "<b>").replace("«", "</b>")
        lines.append(
            f"📡 <b>{esc(r.get('channel_title', ''))}</b> "
            f"({esc(r.get('channel_username', ''))})\n"
            f"📅 {esc(r['date'][:16])} · {esc(r.get('sender_name', ''))}\n"
            f"{snippet}"
        )
        lines.append("")
    await _send(update, "\n".join(lines))


async def cmd_iocs(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ioc_type = _args(ctx) or None
    if ioc_type and ioc_type not in (
        "ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256",
        "email", "cve", "onion", "btc", "eth", "xmr",
    ):
        # Treat as a value search
        return await cmd_ioc_lookup(update, ctx)

    summary = await db.get_ioc_summary()
    if not summary:
        await _send(update, "No IOCs extracted yet. Monitor some channels first.")
        return

    lines = ["📊 <b>Extracted IOC Summary</b>", ""]
    for s in summary:
        lines.append(f"  • <b>{s['ioc_type']}</b>: {s['unique_count']} unique ({s['total']} total)")
    lines.append("")
    lines.append("Drill down: <code>/ioc &lt;value&gt;</code> or <code>/iocs &lt;type&gt;</code>")

    if ioc_type:
        iocs = await db.search_iocs(ioc_type=ioc_type, limit=20)
        lines.append(f"\n🔍 <b>Recent {esc(ioc_type)} IOCs</b>")
        for i in iocs:
            lines.append(
                f"  • <code>{esc(i['value'][:60])}</code> "
                f"– {esc(i['channel_title'])} ({esc(i['first_seen'][:16])})"
            )

    await _send(update, "\n".join(lines))


async def cmd_ioc_lookup(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    value = _args(ctx)
    if not value:
        await _send(update, "Usage: <code>/ioc &lt;value&gt;</code>")
        return

    results = await db.search_iocs(value=value, limit=20)
    if not results:
        await _send(update, f"❌ No sightings of <code>{esc(value)}</code>.")
        return

    lines = [f"🔍 <b>IOC: </b><code>{esc(value)}</code>", ""]
    for r in results:
        lines.append(
            f"  📡 {esc(r.get('channel_title', ''))} | "
            f"{esc(r['ioc_type'])} | {esc(r['first_seen'][:16])}\n"
            f"  💬 {esc((r.get('text') or '')[:120])}"
        )
        lines.append("")
    await _send(update, "\n".join(lines))


async def cmd_timeline(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    value = _args(ctx)
    if not value:
        await _send(update, "Usage: <code>/timeline &lt;ioc_value&gt;</code>")
        return

    sightings = await db.get_ioc_timeline(value)
    if not sightings:
        await _send(update, f"❌ No timeline for <code>{esc(value)}</code>.")
        return

    lines = [f"📈 <b>Timeline for </b><code>{esc(value)}</code>", ""]
    for s in sightings:
        lines.append(
            f"  📅 {esc(s['date'][:16])} | 📡 {esc(s['channel_title'])} "
            f"(@{esc(s.get('channel_username', ''))})\n"
            f"  💬 {esc((s.get('text') or '')[:100])}"
        )
        lines.append("")
    await _send(update, "\n".join(lines))


# ── Alerts ────────────────────────────────────────────────────────────

async def cmd_alert(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    parts = list(ctx.args) if ctx.args else []
    if not parts:
        await _send(update, "Usage:\n"
                            "  <code>/alert add &lt;keyword&gt;</code>\n"
                            "  <code>/alert add_regex &lt;pattern&gt;</code>\n"
                            "  <code>/alert remove &lt;keyword&gt;</code>\n"
                            "  <code>/alert list</code>")
        return

    action = parts[0].lower()
    arg = " ".join(parts[1:])

    if action == "add" and arg:
        ok = await _scanner.add_keyword(arg, is_regex=False)
        emoji = "✅" if ok else "ℹ️"
        msg = "added" if ok else "already exists"
        await _send(update, f"{emoji} Keyword <code>{esc(arg)}</code> {msg}.")

    elif action == "add_regex" and arg:
        ok = await _scanner.add_keyword(arg, is_regex=True)
        emoji = "✅" if ok else "ℹ️"
        msg = "added" if ok else "already exists"
        await _send(update, f"{emoji} Regex <code>{esc(arg)}</code> {msg}.")

    elif action == "remove" and arg:
        ok = await _scanner.remove_keyword(arg)
        await _send(update, f"{'✅ Removed' if ok else '❌ Not found'}: <code>{esc(arg)}</code>")

    elif action == "list":
        keywords = await db.get_alert_keywords()
        if not keywords:
            await _send(update, "No alert keywords configured.")
            return
        lines = ["🔔 <b>Alert Keywords</b>", ""]
        for kw in keywords:
            mode = "regex" if kw["is_regex"] else "keyword"
            lines.append(f"  • <code>{esc(kw['keyword'])}</code> ({mode})")
        await _send(update, "\n".join(lines))
    else:
        await _send(update, "Invalid action. Use: add, add_regex, remove, list")


async def cmd_alerts(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    alerts = await db.get_recent_alerts(limit=20, unack_only=True)
    if not alerts:
        await _send(update, "✅ No unacknowledged alerts.")
        return

    lines = [f"🚨 <b>{len(alerts)} Recent Alert(s)</b>", ""]
    for a in alerts:
        lines.append(
            f"🔔 <b>{esc(a['keyword'])}</b> in {esc(a['channel_title'])}\n"
            f"📅 {esc(a['fired_at'][:16])}\n"
            f"💬 {esc(a['snippet'][:150])}"
        )
        lines.append("")
    await _send(update, "\n".join(lines))


# ── Stats & export ────────────────────────────────────────────────────

async def cmd_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    stats = await db.get_stats()
    lines = [
        "📊 <b>Scanner Stats</b>", "",
        f"  📡 Channels tracked: {stats['channels']} ({stats['monitored']} monitored)",
        f"  💬 Messages collected: {stats['messages']}",
        f"  🔍 IOCs extracted: {stats['iocs']}",
        f"  🚨 Alerts fired: {stats['alerts']} ({stats['unack_alerts']} unread)",
    ]
    await _send(update, "\n".join(lines))


async def cmd_export(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    data = await db.export_all()
    text = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    if len(text) > MAX_MSG:
        # Send as file
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                          delete=False, prefix="cti_export_") as f:
            f.write(text)
            path = f.name
        try:
            with open(path, "rb") as fh:
                await update.message.reply_document(
                    document=fh,
                    filename="cti_export.json",
                    caption="📦 Full CTI scanner export",
                )
        finally:
            os.unlink(path)
    else:
        await _send(update, f"<pre>{esc(text[:MAX_MSG])}</pre>")


# ══════════════════════════════════════════════════════════════════════
#  SETUP
# ══════════════════════════════════════════════════════════════════════

async def post_init(app: Application):
    commands = [
        BotCommand("help",      "Show all commands"),
        BotCommand("scan",      "Search for Telegram channels"),
        BotCommand("resolve",   "Get channel info"),
        BotCommand("monitor",   "Join & monitor a channel"),
        BotCommand("unmonitor", "Stop monitoring"),
        BotCommand("channels",  "List tracked channels"),
        BotCommand("search",    "Full-text search messages"),
        BotCommand("iocs",      "IOC summary / browse"),
        BotCommand("ioc",       "Look up a specific IOC"),
        BotCommand("timeline",  "IOC sighting timeline"),
        BotCommand("alert",     "Manage alert keywords"),
        BotCommand("alerts",    "Show recent alerts"),
        BotCommand("stats",     "Dashboard stats"),
    ]
    await app.bot.set_my_commands(commands)


def create_bot_app() -> Application:
    if not config.BOT_TOKEN:
        return None

    app = (
        Application.builder()
        .token(config.BOT_TOKEN)
        .post_init(post_init)
        .build()
    )

    app.add_handler(CommandHandler("start",     cmd_help))
    app.add_handler(CommandHandler("help",      cmd_help))
    app.add_handler(CommandHandler("scan",      cmd_scan))
    app.add_handler(CommandHandler("resolve",   cmd_resolve))
    app.add_handler(CommandHandler("monitor",   cmd_monitor))
    app.add_handler(CommandHandler("unmonitor", cmd_unmonitor))
    app.add_handler(CommandHandler("channels",  cmd_channels))
    app.add_handler(CommandHandler("backfill",  cmd_backfill))
    app.add_handler(CommandHandler("search",    cmd_search))
    app.add_handler(CommandHandler("iocs",      cmd_iocs))
    app.add_handler(CommandHandler("ioc",       cmd_ioc_lookup))
    app.add_handler(CommandHandler("timeline",  cmd_timeline))
    app.add_handler(CommandHandler("alert",     cmd_alert))
    app.add_handler(CommandHandler("alerts",    cmd_alerts))
    app.add_handler(CommandHandler("stats",     cmd_stats))
    app.add_handler(CommandHandler("export",    cmd_export))

    return app
