# CTI Telegram Scanner

Monitors Telegram channels where threat actors operate. Extracts IOCs, detects stealer log posts, and stores everything in a searchable database with a web dashboard.

---

## What it does

- **Channel monitoring** - Real-time message capture with history backfill. Managed from the web UI.
- **IOC extraction** - IPs, domains, URLs, hashes, emails, CVEs, .onion, crypto wallets. Handles defanged formats.
- **Stealer log detection** - Family identification, log counts, countries, data types, pricing, download links.
- **Smart filtering** - Relevance engine drops noise, keeps messages with IOCs/keywords/stealer content. Toggleable from the UI.
- **Auto-discovery** - Finds new channels on a schedule, queues them for manual approval.
- **Keyword alerting** - Plain-text or regex patterns with optional ntfy push notifications.
- **Dashboard** - IOC trends, cross-channel correlation, stealer family breakdown, full-text search, light/dark mode.

---

## OPSEC

- Use a dedicated Telegram account, not your personal one.
- The `.session` file is your Telegram login. Treat it like a credential.
- Channel joins are visible in the member list.
- Telegram rate limits aggressive activity. The scanner handles flood waits, but don't mass-join.
- You are responsible for legal compliance in your jurisdiction.

---

## Tuning

The default keywords and filters are a starting point. Expect some noise during initial setup and tune the scanner for your specific intelligence requirements.

Alert keywords can be set in `.env` as a comma-separated list:

```env
ALERT_KEYWORDS=ransomware,stealer log,CVE-,0day,zero-day,data leak,credential dump
```

Keywords can also be managed from **Settings > Keywords**, while **Settings > Filters** controls relevance filtering, IOC types, ignored domains, stealer detection, and other collection criteria.

Let the scanner collect some data, review the results, and adjust the settings until you're satisfied. Once tuning is complete, clear the test data and start fresh:

```bash
python reset_data.py
```

This removes collected data while preserving your configured channels and keywords.

---

## Quick start

```bash
git clone https://github.com/yourname/cti-telegram-scanner.git
cd cti-telegram-scanner
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your Telegram API credentials from https://my.telegram.org
python main.py
```
First run prompts for a login code. Enter it once, session is cached after that. Open `http://localhost:8080`, go to Settings > Channels, add a channel.

If port 8080 is already in use, change `WEB_PORT` in your `.env`:

```
WEB_PORT=9090
```
---

## Docker

```yaml
services:
  cti-scanner:
    build: .
    container_name: cti-scanner
    restart: unless-stopped
    env_file: .env
    volumes:
      - cti_data:/app/data
      - cti_archives:/app/archives
    ports:
      - "8080:8080"

volumes:
  cti_data:
  cti_archives:
```

First-run Telegram login must be done interactively. See the [Docker setup docs](COMPANION-BOT.md) or run:
```bash
docker compose run --rm cti-scanner python main.py
```
Enter the Telegram login code when prompted.

---

## Notifications

Optional. Configure ntfy from **Settings > Notifications** or via `.env`:

```text
NTFY_URL=https://ntfy.example.com
NTFY_TOPIC=cti-alerts
NTFY_TOKEN=tk_your_token_here
```

Sends keyword alerts, health warnings, recovery notices, retention summaries, and discovery notifications.

---

## Database

SQLite by default (zero config, FTS5 search). Elasticsearch available as a drop-in alternative via `DB_BACKEND=elasticsearch` in `.env`.

---

## API

| Endpoint | Description |
|---|---|
| `GET /api/health` | Scanner health (200/503) |
| `GET /api/search?q=...` | Search messages and IOCs |
| `GET /api/stats` | Dashboard stats |
| `GET /api/iocs?type=&value=` | Query IOCs |
| `GET /api/export` | Full database export |

---

## Utilities

```bash
python reset_data.py      # purge collected data after tuning; keep channels/keywords
python migrate.py         # add new tables after updating
python main.py --web-only # browse DB without scanner running
```

---

## License

MIT
