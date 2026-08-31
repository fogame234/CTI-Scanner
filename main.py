#!/usr/bin/env python3
"""
CTI Telegram Scanner — main entry point.

Launches three components:
  1. Telethon scanner  – discovers / monitors channels, extracts IOCs
  2. Companion bot     – (optional) Telegram bot for /scan, /search commands
  3. Web UI            – (optional) searchable dashboard at http://localhost:8080

Usage:
  python main.py                    # scanner + web UI
  python main.py --no-web           # scanner only
  python main.py --web-only         # web UI only (browse existing DB)
"""

import argparse
import asyncio
import logging
import sys

logging.basicConfig(
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("cti-main")


def main():
    parser = argparse.ArgumentParser(description="CTI Telegram Scanner")
    parser.add_argument("--no-web", action="store_true", help="Skip the web UI")
    parser.add_argument("--web-only", action="store_true", help="Only run the web UI")
    parser.add_argument("--no-bot", action="store_true", help="Skip the companion bot")
    args = parser.parse_args()

    import config

    if args.web_only:
        logger.info("Running web UI only …")
        from web import create_app
        from aiohttp import web as aio_web
        import db_router as db
        app = create_app()
        aio_web.run_app(app, host=config.WEB_HOST, port=config.WEB_PORT)
        return

    # Validate required config
    if not config.API_ID or not config.API_HASH:
        logger.error(
            "TELEGRAM_API_ID and TELEGRAM_API_HASH are required.\n"
            "Get them from https://my.telegram.org → API development tools.\n"
            "See README.md for setup instructions."
        )
        sys.exit(1)

    # Create the event loop first — Telethon binds to whichever loop
    # exists when TelegramClient is created, so it must exist before.
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Run the scanner (blocking)
    from scanner import CTIScanner
    scanner = CTIScanner()
    scanner._loop = loop  # store for web UI cross-thread calls

    # Start web UI in background (with scanner reference for management)
    if not args.no_web:
        from web import start_web_background
        start_web_background(scanner=scanner)

    # Start companion bot in background (if token configured)
    # Must happen after scanner is created so it can share the instance
    if not args.no_bot and config.BOT_TOKEN:
        _start_bot_background(scanner)

    try:
        loop.run_until_complete(scanner.run_forever())
    except KeyboardInterrupt:
        logger.info("Shutting down …")
        loop.run_until_complete(scanner.stop())
    finally:
        loop.close()


def _start_bot_background(scanner):
    """Start the companion Telegram bot in a background thread.
    
    Receives the main scanner instance so the bot can call its methods
    (search, join, etc.) without opening a second Telethon session.
    """
    import threading

    def _run():
        from bot import create_bot_app, set_scanner

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        set_scanner(scanner)

        bot_app = create_bot_app()
        if bot_app:
            logger.info("🤖 Companion bot starting …")
            bot_app.run_polling(allowed_updates=["message"])

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    logger.info("🤖 Companion bot thread started.")


if __name__ == "__main__":
    main()
