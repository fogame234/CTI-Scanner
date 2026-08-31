# CTI Telegram Scanner

A threat intelligence tool that monitors Telegram channels where threat actors operate, extracts indicators of compromise from every message, detects stealer log posts, and stores everything in a searchable database with a web dashboard. Built for analysts who need to track the Telegram threat landscape without manually watching dozens of channels.

---

## What it does

- **Channel monitoring** - Joins Telegram channels, captures messages in real time, backfills history on first join. Managed entirely from the web UI.
- **IOC extraction** - Pulls IPs, domains, URLs, hashes, emails, CVEs, .onion addresses, and crypto wallets from every message. Handles defanged formats.
- **Stealer log detection** - Identifies stealer log posts and extracts family, log count, countries, data types, pricing, and download links.
- **Smart filtering** - Only stores messages with IOCs, keyword matches, or stealer content. Drops spam and noise. All filters toggleable from the UI.
- **Auto-discovery** - Searches Telegram for new channels on a schedule, presents candidates for manual approval.
- **Keyword alerting** - Plain-text or regex patterns that trigger alerts and optional ntfy push notifications.
- **Web dashboard** - IOC trends, cross-channel correlation, stealer family breakdown, full-text search, IOC detail pages. Light and dark mode.
- **Health monitoring** - Connection tracking, stale detection, /api/health endpoint for uptime monitors.
- **Data retention** - Archives and purges old data on a configurable schedule.
- **ntfy notifications** - Optional push notifications for alerts, health, and discovery. Configurable from the web UI or .env.

---

## Quick Start

### Prerequisites

- Python 3.12+
- A Telegram account (dedicated account recommended for production)
- Telegram API credentials from [my.telegram.org](https://my.telegram.org)

### Install

```bash
git clone https://github.com/yourname/cti-telegram-scanner.git
cd cti-telegram-scanner
pip install -r requirements.txt
cp .env.example .env
```

### Configure

Edit `.env` and add your Telegram API credentials:

```
TELEGRAM_API_ID=your_api_id
TELEGRAM_API_HASH=your_api_hash
TELEGRAM_PHONE=+1234567890
```

### Run

```bash
python main.py
```

On first run, Telethon prompts for the login code sent to your phone. Enter it once and the session is cached after that.

Open `http://localhost:8080` to access the dashboard.

### Add channels

Go to **Settings > Channels**, paste a channel @handle or invite link, and click "Join & monitor." The scanner starts collecting immediately.

---

## Docker

```dockerfile
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/data /app/archives
CMD ["python", "main.py"]
```

### Docker Compose

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
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; r = urllib.request.urlopen('http://localhost:8080/api/health'); exit(0 if r.status == 200 else 1)"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 45s

volumes:
  cti_data:
  cti_archives:
```

### First-run Telethon login (Docker)

The Telegram login is interactive and must be done once before the container can run unattended:

```bash
docker compose run --rm cti-scanner python -c "
from telethon.sync import TelegramClient
import os
c = TelegramClient(
    '/app/data/cti_scanner',
    int(os.environ['TELEGRAM_API_ID']),
    os.environ['TELEGRAM_API_HASH']
)
c.start(phone=os.environ['TELEGRAM_PHONE'])
print('Session created.')
c.disconnect()
"
```

After entering the code, start the service normally:

```bash
docker compose up -d
```

---

## Reverse Proxy & Authentication

The web UI has no built-in authentication. In production, put it behind a reverse proxy with authentication to protect the settings, alerts, and management endpoints.

### What should be public vs protected

**Public (read-only):** Dashboard, Channels, IOCs, IOC detail, Stealer logs, Search, Health, Discovery.

**Protected (requires login):** Settings (all tabs), Alerts, Export, and all POST endpoints (adding channels, changing filters, acknowledging alerts, approving discoveries).

### Traefik + Authelia

Create two routers on the same domain. The public router serves GET requests to read-only pages without authentication. The protected router catches `/settings`, `/alerts`, `/api/export`, and all POST methods, with your auth middleware applied.

### Nginx + Basic Auth

```nginx
server {
    listen 443 ssl;
    server_name cti.example.com;

    location / {
        proxy_pass http://localhost:8080;
    }

    location /settings {
        auth_basic "Admin";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://localhost:8080;
    }

    location /alerts {
        auth_basic "Admin";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://localhost:8080;
    }

    location /api/export {
        auth_basic "Admin";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://localhost:8080;
    }
}
```

### Caddy

```
cti.example.com {
    reverse_proxy localhost:8080

    @protected {
        path /settings* /alerts* /api/export*
    }
    basicauth @protected {
        admin JDJhJDE0JC... # caddy hash-password
    }
}
```

### No reverse proxy

If running locally or on a trusted network, access the UI directly at `http://localhost:8080`. All features are available without authentication.

---

## Notifications (ntfy)

Push notifications are optional. They can be configured entirely from the web UI under **Settings > Notifications**, or via `.env` for automated deployments.

### From the web UI

1. Go to **Settings > Notifications**
2. Toggle notifications on
3. Enter your ntfy server URL and topic
4. Add an access token if your server requires authentication
5. Click **Save**, then **Send test notification**

### From .env

```
NTFY_URL=https://ntfy.example.com
NTFY_TOPIC=cti-alerts
NTFY_TOKEN=tk_your_token_here
```

Values set in `.env` are automatically imported into the database on first startup. After that, the web UI is the source of truth.

### Self-hosted ntfy with token auth

If your ntfy server uses `deny-all` default access:

```bash
docker exec -it ntfy sh
ntfy user add cti-scanner
ntfy access cti-scanner cti-alerts rw
ntfy token add cti-scanner
exit
```

Copy the `tk_...` token into the settings.

### ntfy.sh (free hosted)

Set the URL to `https://ntfy.sh` and pick a unique topic name. No token needed for public topics.

### What gets notified

- **Keyword alerts** - when a monitored channel posts a message matching your keywords
- **Health warnings** - scanner disconnect or stale data (no messages received)
- **Recovery** - scanner back online after a health warning
- **Retention** - summary after each archival/purge run
- **Discovery** - new channel candidates found

---

## Settings

All configuration is available from the web UI under **Settings**, organized into tabs:

**General** - Scanner status, backfill limit, data management commands.

**Channels** - Search Telegram for channels, add by handle or invite link, monitor/unmonitor, force backfill.

**Keywords** - Add and remove alert keywords (plain text or regex).

**Filters** - Toggle filters on/off without restarting:
- Master filter (on/off for all filtering)
- Relevance only (only keep messages with IOCs, keywords, or stealer content)
- Spam filter (blocks VIP bait, fake giveaways)
- Skip private IPs (drops RFC1918 addresses)
- Stealer require download (only keep stealer logs with a download link)
- Editable: min message length, stealer confidence threshold, IOC types, ignored domains

**Notifications** - ntfy configuration with a test button.

---

## Architecture

```
main.py              Entry point, launches scanner, web UI, optional bot
scanner.py           Telethon client, channel discovery, monitoring, IOC extraction
web.py               Web dashboard and management UI (aiohttp)
db.py                SQLite database with FTS5 full-text search
db_elastic.py        Elasticsearch backend (drop-in alternative)
db_router.py         Routes to the active database backend
filters.py           Runtime-configurable message and IOC filters
notify.py            ntfy push notification integration
health.py            Health check tracking and stale detection
retention.py         Data archival and purge scheduling
config.py            Environment-based configuration
bot.py               Optional companion Telegram bot (see COMPANION-BOT.md)
migrate.py           Database migration for schema updates
reset_data.py        Purge collected data while keeping channel config
setup_kibana.py      Kibana data view setup for Elasticsearch
utils/
  extractor.py       IOC extraction engine
  stealer_parser.py  Stealer log detection and metadata parsing
```

---

## Database

### SQLite (default)

Zero configuration. The database is a single file (`cti_scanner.db`). Full-text search is provided by FTS5. Suitable for most deployments.

### Elasticsearch

Set `DB_BACKEND=elasticsearch` in `.env`. Provides aggregation queries (IOC co-occurrence, channel volume histograms), scales to large datasets, and integrates with Kibana for visualization. Run `python setup_kibana.py` after starting Elasticsearch to create data views.

Switching backends is a one-line change in `.env`. Both expose the same interface, and the scanner, web UI, and all features work identically on either backend.

---

## Utilities

**Reset data** - Purge all collected data while keeping channels and keywords:
```bash
python reset_data.py
```

**Migrate** - Add new database tables after updating:
```bash
python migrate.py
```

**Web-only mode** - Browse an existing database without running the scanner:
```bash
python main.py --web-only
```

---

## API

All data is available via JSON endpoints:

| Endpoint | Description |
|---|---|
| `GET /api/health` | Scanner health status (200 or 503) |
| `GET /api/search?q=...` | Search messages and IOCs |
| `GET /api/stats` | Dashboard statistics |
| `GET /api/iocs?type=&value=` | Query extracted IOCs |
| `GET /api/export` | Full database export |

---

## OPSEC

- **Use a dedicated Telegram account.** Do not run this on your personal account. Create a separate account for collection.
- **Session security.** The `.session` file is your Telegram login. Treat it like a credential. It is excluded from git by default.
- **Channel joining is visible.** When the scanner joins a channel, the account appears in the member list.
- **Rate limits.** Telegram throttles aggressive activity. The scanner handles flood waits automatically, but avoid mass-joining dozens of channels at once.
- **Legal responsibility.** You are responsible for compliance with applicable laws in your jurisdiction.

---

## License

MIT
