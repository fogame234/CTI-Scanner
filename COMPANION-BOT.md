# Companion Telegram bot (optional)

The scanner works fully without this. The companion bot gives you a
Telegram-native command interface so you can issue queries and manage
monitoring from any Telegram chat instead of using the web dashboard.

## What it adds

The bot runs alongside the scanner and provides these commands:

**Channel discovery**
- `/scan <keyword>` — search Telegram for matching channels
- `/resolve <@handle or link>` — get info about a specific channel

**Monitoring**
- `/monitor <@channel>` — join a channel and start collecting
- `/unmonitor <channel_id>` — stop monitoring (does not leave the channel)
- `/channels` — list all tracked channels with status
- `/backfill <channel_id>` — force re-scrape a channel's history

**Search and IOCs**
- `/search <query>` — full-text search all collected messages
- `/iocs [type]` — IOC summary or browse by type
- `/ioc <value>` — find all sightings of a specific indicator
- `/timeline <value>` — chronological sighting history for an IOC

**Alerting**
- `/alert add <keyword>` — add a plain-text alert keyword
- `/alert add_regex <pattern>` — add a regex alert pattern
- `/alert remove <keyword>` — remove a keyword
- `/alert list` — show active keywords
- `/alerts` — show recent unacknowledged alerts

**Utility**
- `/stats` — dashboard numbers
- `/export` — full JSON data export (sent as a file if large)
- `/help` — command reference

## Setup

### 1. Create the bot with BotFather

Open Telegram and message [@BotFather](https://t.me/BotFather):

1. Send `/newbot`
2. Choose a name (e.g. "CTI Scanner Bot")
3. Choose a username (e.g. "my_cti_scanner_bot")
4. BotFather replies with a token like `7123456789:AAF...`

### 2. Add the token to your .env

Open your scanner's `.env` file and set:

```
TELEGRAM_BOT_TOKEN=7123456789:AAFyour_token_here
```

### 3. Restart the scanner

```bash
docker compose restart cti-scanner
```

The scanner detects the token on startup and launches the bot
automatically in a background thread. You'll see this in the logs:

```
🤖 Companion bot thread started.
```

### 4. Start using it

Open Telegram, find your bot by the username you chose, and send
`/help` to see all available commands.

## Security notes

- The bot is public by default — anyone who finds it can issue
  commands. If you want to restrict access, you can either keep the
  bot username private (security through obscurity, not recommended
  long term), or add an `ALLOWED_USER_IDS` check to `bot.py`.

- To find your Telegram user ID, message [@userinfobot](https://t.me/userinfobot)
  on Telegram. It replies with your numeric ID.

- The bot uses the standard Telegram Bot API. It cannot search for
  channels or read channel history — that's the scanner's job using
  the client API. The bot is purely a command interface that calls
  the scanner's methods.

## Disabling

To disable the bot, simply remove or blank out `TELEGRAM_BOT_TOKEN`
in your `.env` and restart the container. The scanner continues
running and collecting without it.
