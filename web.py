"""
Web UI for browsing and managing the CTI scanner.

Mobile-friendly dashboard: channels, messages, IOCs, alerts — all searchable.
Includes channel management, keyword management, and settings.
Runs on port 8080 by default.
"""

import json
import logging
import asyncio
import threading
from html import escape as esc

from aiohttp import web

import config
import db_router as db
import filters as f
from csrf import csrf_middleware, csrf_field

logger = logging.getLogger(__name__)

# Scanner reference — set by main.py when scanner is running.
# None when running in --web-only mode (read-only).
_scanner = None

def set_scanner(scanner):
    global _scanner
    _scanner = scanner

def _scanner_available() -> bool:
    return _scanner is not None


async def _call_scanner(coro_func, *args, **kwargs):
    """
    Call a scanner coroutine from the web's event loop.
    The scanner runs on a different thread/loop, so we schedule
    the coroutine there and wait for the result.
    """
    if not _scanner:
        return None
    # The scanner's client has its own loop
    loop = _scanner.client.loop
    future = asyncio.run_coroutine_threadsafe(coro_func(*args, **kwargs), loop)
    # Wait with a timeout so we don't hang the web request
    return future.result(timeout=30)


# ══════════════════════════════════════════════════════════════════════
#  TEMPLATES
# ══════════════════════════════════════════════════════════════════════

_CSS = """
:root{--bg:#f6f8fa;--sf:#ffffff;--bd:#d0d7de;--tx:#1f2328;--mt:#656d76;
--ac:#0969da;--gn:#1a7f37;--yl:#9a6700;--or:#bc4c00;--rd:#cf222e;
--fn:'Segoe UI',system-ui,sans-serif;--mo:'SF Mono','Fira Code',monospace}
@media(prefers-color-scheme:dark){
:root:not([data-theme=light]){--bg:#0d1117;--sf:#161b22;--bd:#30363d;--tx:#e6edf3;--mt:#8b949e;
--ac:#58a6ff;--gn:#3fb950;--yl:#d29922;--or:#db6d28;--rd:#f85149}}
[data-theme=dark]{--bg:#0d1117;--sf:#161b22;--bd:#30363d;--tx:#e6edf3;--mt:#8b949e;
--ac:#58a6ff;--gn:#3fb950;--yl:#d29922;--or:#db6d28;--rd:#f85149}
[data-theme=light]{--bg:#f6f8fa;--sf:#ffffff;--bd:#d0d7de;--tx:#1f2328;--mt:#656d76;
--ac:#0969da;--gn:#1a7f37;--yl:#9a6700;--or:#bc4c00;--rd:#cf222e}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--tx);font-family:var(--fn);line-height:1.6}
a{color:var(--ac);text-decoration:none}a:hover{text-decoration:underline}
.c{max-width:1100px;margin:0 auto;padding:1rem}
nav{background:var(--sf);border-bottom:1px solid var(--bd);padding:.6rem 1rem;
display:flex;align-items:center;gap:1.2rem;flex-wrap:wrap;position:sticky;top:0;z-index:10}
nav .b{font-weight:700;font-size:1.1rem;color:var(--ac)}
nav a{color:var(--mt);font-size:.85rem}nav a:hover{color:var(--tx)}
.sb{display:flex;gap:.4rem;margin:1.2rem 0}
.sb input{flex:1;padding:.5rem .8rem;border:1px solid var(--bd);border-radius:6px;
background:var(--sf);color:var(--tx);font-size:.95rem;font-family:var(--mo)}
.sb input:focus{outline:none;border-color:var(--ac)}
.sb button{padding:.5rem 1rem;background:var(--ac);color:#000;border:none;
border-radius:6px;cursor:pointer;font-weight:600}
.card{background:var(--sf);border:1px solid var(--bd);border-radius:8px;
padding:.9rem 1.1rem;margin-bottom:.65rem}
.card h3{margin-bottom:.2rem}.meta{color:var(--mt);font-size:.82rem}
.badge{display:inline-block;padding:.1rem .45rem;border-radius:10px;
font-size:.72rem;font-weight:600;margin-left:.3rem}
.badge.on{background:var(--gn);color:#000}.badge.off{background:var(--bd);color:var(--mt)}
.badge.alert{background:var(--rd);color:#fff}
.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.6rem;margin:1.2rem 0}
.st{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:.8rem;text-align:center}
.st .n{font-size:1.8rem;font-weight:700;color:var(--ac)}.st .l{color:var(--mt);font-size:.8rem}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th,td{padding:.4rem .6rem;text-align:left;border-bottom:1px solid var(--bd)}
th{color:var(--mt);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.04em}
td code{font-family:var(--mo);font-size:.82rem;background:var(--bg);
padding:.08rem .25rem;border-radius:3px}
.snippet{color:var(--mt);font-size:.82rem}
.snippet b{color:var(--tx);font-weight:600}
pre{background:var(--bg);border:1px solid var(--bd);border-radius:6px;
padding:.8rem;overflow-x:auto;font-size:.82rem;font-family:var(--mo);
white-space:pre-wrap;word-break:break-word}
.empty{text-align:center;color:var(--mt);padding:2.5rem}
.tabs{display:flex;gap:.4rem;margin:1rem 0}
.tabs a{padding:.3rem .8rem;border-radius:6px;background:var(--sf);
border:1px solid var(--bd);font-size:.82rem;color:var(--mt)}
.tabs a.active,.tabs a:hover{color:var(--tx);border-color:var(--ac)}
.theme-btn{background:none;border:1px solid var(--bd);border-radius:6px;
padding:.2rem .5rem;cursor:pointer;font-size:.85rem;color:var(--mt);margin-left:auto}
.theme-btn:hover{color:var(--tx);border-color:var(--ac)}
"""

def _page(title, body, query="", csrf=""):
    html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} – CTI Scanner</title>
<style>{_CSS}</style>
<script>
(function(){{
  var t=localStorage.getItem('theme');
  if(t)document.documentElement.setAttribute('data-theme',t);
}})();
function toggleTheme(){{
  var r=document.documentElement;
  var c=r.getAttribute('data-theme');
  var n=(c==='dark')?'light':(c==='light')?'dark':
    (window.matchMedia('(prefers-color-scheme:dark)').matches?'light':'dark');
  r.setAttribute('data-theme',n);
  localStorage.setItem('theme',n);
  document.getElementById('tbtn').textContent=(n==='dark')?'☀️':'🌙';
}}
</script>
</head><body>
<nav>
<span class="b">🛡️ CTI Scanner</span>
<a href="/">Dashboard</a><a href="/channels">Channels</a>
<a href="/iocs">IOCs</a><a href="/stealer-logs">Stealer logs</a><a href="/alerts">Alerts</a>
<a href="/health">Health</a><a href="/discovery">Discovery</a><a href="/settings">Settings</a><a href="/api/export">Export</a>
<button class="theme-btn" id="tbtn" onclick="toggleTheme()">🌙</button>
</nav>
<div class="c">
<form class="sb" action="/search"><input name="q" placeholder="Search messages, IOCs, channels …"
value="{esc(query)}" autofocus><button>Search</button></form>
{body}</div>
<script>
(function(){{
  var t=document.documentElement.getAttribute('data-theme');
  if(!t)t=window.matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light';
  document.getElementById('tbtn').textContent=(t==='dark')?'☀️':'🌙';
}})();
</script>
</body></html>"""
    # Inject CSRF hidden field after every <form ... method="post">
    if csrf:
        import re as _re
        html = _re.sub(r'(method="post"[^>]*>)', r'\1' + csrf, html)
    return html


# ══════════════════════════════════════════════════════════════════════
#  HANDLERS
# ══════════════════════════════════════════════════════════════════════

async def h_dashboard(req):
    stats = await db.get_stats()
    ioc_summary = await db.get_ioc_summary()
    iocs_per_day = await db.get_iocs_per_day(30)
    recent_iocs = await db.get_recent_iocs(10)
    top_iocs = await db.get_top_iocs(10)
    active_channels = await db.get_active_channels(7, 8)
    stealer_families = await db.get_stealer_family_counts(30)
    stealer_total = sum(stealer_families.values()) if stealer_families else 0

    # ── Stat cards ────────────────────────────────────────────────────
    body = f"""<h2 style="display:flex;align-items:center;gap:10px">Dashboard <button onclick="location.reload()" style="padding:4px 12px;background:var(--ac);color:#000;border:none;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer">Refresh</button></h2>
    <div class="sg">
      <a href="/channels" class="st" style="text-decoration:none;color:inherit"><div class="n">{stats['monitored']}</div><div class="l">Monitored</div></a>
      <a href="/channels" class="st" style="text-decoration:none;color:inherit"><div class="n">{stats['channels']}</div><div class="l">Channels</div></a>
      <a href="/channels" class="st" style="text-decoration:none;color:inherit"><div class="n">{stats['messages']}</div><div class="l">Messages</div></a>
      <a href="/iocs" class="st" style="text-decoration:none;color:inherit"><div class="n">{stats['iocs']}</div><div class="l">IOCs</div></a>
      <a href="/stealer-logs" class="st" style="text-decoration:none;color:inherit"><div class="n">{stealer_total}</div><div class="l">Stealer Logs</div></a>
    </div>"""

    # ── IOC activity graph (last 30 days) ─────────────────────────────
    if iocs_per_day:
        max_count = max(d["count"] for d in iocs_per_day) or 1
        chart_w = 700
        chart_h = 160
        bar_gap = 2
        bar_w = max((chart_w - 60) // max(len(iocs_per_day), 1) - bar_gap, 4)
        x_start = 40

        bars_svg = ""
        labels_svg = ""
        for idx, d in enumerate(iocs_per_day):
            x = x_start + idx * (bar_w + bar_gap)
            bar_h = max(int((d["count"] / max_count) * (chart_h - 30)), 2)
            y = chart_h - bar_h - 15
            bars_svg += f'<rect x="{x}" y="{y}" width="{bar_w}" height="{bar_h}" fill="var(--ac)" rx="2" opacity="0.85"><title>{d["day"]}: {d["count"]} IOCs</title></rect>'
            if idx % max(len(iocs_per_day) // 6, 1) == 0:
                labels_svg += f'<text x="{x}" y="{chart_h - 2}" font-size="9" fill="var(--mt)" font-family="var(--fn)">{d["day"][5:]}</text>'

        # Y-axis labels
        y_labels = ""
        for frac in (0, 0.5, 1.0):
            val = int(max_count * (1 - frac))
            y = 10 + int(frac * (chart_h - 30))
            y_labels += f'<text x="35" y="{y + 3}" font-size="9" fill="var(--mt)" text-anchor="end" font-family="var(--fn)">{val}</text>'
            y_labels += f'<line x1="{x_start}" y1="{y}" x2="{chart_w}" y2="{y}" stroke="var(--bd)" stroke-width="0.5" stroke-dasharray="3,3"/>'

        body += f'''<div class="card">
          <h3>IOC activity (last 30 days)</h3>
          <svg viewBox="0 0 {chart_w} {chart_h}" style="width:100%;height:auto;margin-top:6px">
            {y_labels}{bars_svg}{labels_svg}
          </svg>
        </div>'''

    # ── Two column layout for tables ──────────────────────────────────
    body += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">'

    # ── Recent IOCs ───────────────────────────────────────────────────
    body += '<div class="card"><h3>Recent IOCs</h3>'
    if recent_iocs:
        body += '<table class="tb"><tr><th>Value</th><th>Type</th><th>Channel</th><th>When</th></tr>'
        for i in recent_iocs:
            body += f'<tr><td><a href="/ioc-detail?value={esc(i["value"])}"><code>{esc(i["value"][:40])}</code></a></td><td>{i["ioc_type"]}</td><td>{esc(i.get("channel_title","")[:20])}</td><td>{esc(i["first_seen"][:16])}</td></tr>'
        body += '</table>'
    else:
        body += '<p style="font-size:12px;color:var(--mt)">No IOCs yet.</p>'
    body += '</div>'

    # ── Top IOCs (most cross-channel sightings) ───────────────────────
    body += '<div class="card"><h3>Top IOCs (cross-channel)</h3>'
    if top_iocs:
        body += '<table class="tb"><tr><th>Value</th><th>Type</th><th>Channels</th><th>Sightings</th></tr>'
        for i in top_iocs:
            body += f'<tr><td><a href="/ioc-detail?value={esc(i["value"])}"><code>{esc(i["value"][:40])}</code></a></td><td>{i["ioc_type"]}</td><td>{i["channels"]}</td><td>{i["sightings"]}</td></tr>'
        body += '</table>'
    else:
        body += '<p style="font-size:12px;color:var(--mt)">No IOCs yet.</p>'
    body += '</div>'

    body += '</div>'  # close grid

    # ── Second row: active channels + IOC breakdown + stealer summary ─
    body += '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px">'

    # ── Active channels (last 7 days) ─────────────────────────────────
    body += '<div class="card"><h3>Active channels (7d)</h3>'
    if active_channels:
        body += '<table class="tb"><tr><th>Channel</th><th>Messages</th></tr>'
        for c in active_channels:
            body += f'<tr><td><a href="/channel/{c["id"]}">{esc(c["title"][:25])}</a></td><td>{c["msg_count"]}</td></tr>'
        body += '</table>'
    else:
        body += '<p style="font-size:12px;color:var(--mt)">No activity yet.</p>'
    body += '</div>'

    # ── IOC breakdown ─────────────────────────────────────────────────
    body += '<div class="card"><h3>IOC breakdown</h3>'
    if ioc_summary:
        body += '<table class="tb"><tr><th>Type</th><th>Unique</th><th>Total</th></tr>'
        for s in ioc_summary:
            body += f'<tr><td><a href="/iocs?type={s["ioc_type"]}">{s["ioc_type"]}</a></td><td>{s["unique_count"]}</td><td>{s["total"]}</td></tr>'
        body += '</table>'
    else:
        body += '<p style="font-size:12px;color:var(--mt)">No IOCs yet.</p>'
    body += '</div>'

    # ── Stealer log summary (last 30 days) ────────────────────────────
    body += '<div class="card"><h3>Stealer families (30d)</h3>'
    if stealer_families:
        body += '<table class="tb"><tr><th>Family</th><th>Count</th></tr>'
        for fam, cnt in list(stealer_families.items())[:10]:
            body += f'<tr><td><a href="/stealer-logs?family={esc(fam)}">{esc(fam)}</a></td><td>{cnt}</td></tr>'
        body += '</table>'
    else:
        body += '<p style="font-size:12px;color:var(--mt)">No stealer logs yet.</p>'
    body += '</div>'

    body += '</div>'  # close grid

    return web.Response(text=_page("Dashboard", body, csrf=csrf_field(req)), content_type="text/html")


async def h_channels(req):
    channels = await db.get_all_channels()
    body = '<h2>Channels</h2>'
    if not channels:
        body += '<div class="empty">No channels tracked. Use the Telegram bot to /monitor channels.</div>'
    else:
        body += '<table><tr><th>Channel</th><th>Type</th><th>Members</th><th>Status</th><th>Last Scraped</th></tr>'
        for c in channels:
            status = '<span class="badge on">ON</span>' if c["is_monitored"] else '<span class="badge off">OFF</span>'
            title_link = f'<a href="/channel/{c["id"]}">{esc(c["title"])}</a>'
            if c["username"]:
                title_link += f' <span class="meta">@{esc(c["username"])}</span>'
            body += f'<tr><td>{title_link}</td><td>{c["channel_type"]}</td><td>{c["participants"]}</td><td>{status}</td><td>{esc((c["last_scraped"] or "never")[:16])}</td></tr>'
        body += '</table>'
    return web.Response(text=_page("Channels", body, csrf=csrf_field(req)), content_type="text/html")


async def h_channel_detail(req):
    cid = int(req.match_info["id"])
    chan = await db.get_channel(cid)
    if not chan:
        return web.Response(text=_page("Not Found", '<div class="empty">Channel not found.</div>'),
                            content_type="text/html", status=404)

    messages = await db.get_channel_messages(cid, limit=50)
    channel_iocs = await db.search_iocs(channel_id=cid, limit=200)

    body = f"""<h2>📡 {esc(chan['title'])}</h2>
    <div class="card">
      <p><b>ID:</b> <code>{cid}</code> · <b>Type:</b> {chan['channel_type']} ·
         <b>Members:</b> {chan['participants']}</p>
      {'<p><b>About:</b> ' + esc(chan["about"][:300]) + '</p>' if chan["about"] else ''}
    </div>"""

    if channel_iocs:
        # Deduplicate by value — keep latest timestamp and count sightings
        seen: dict[str, dict] = {}
        for i in channel_iocs:
            v = i["value"]
            if v not in seen:
                seen[v] = {"ioc_type": i["ioc_type"], "value": v,
                           "latest": i["first_seen"], "count": 1}
            else:
                seen[v]["count"] += 1
                if i["first_seen"] > seen[v]["latest"]:
                    seen[v]["latest"] = i["first_seen"]

        body += f'<div class="card"><h3>Extracted IOCs ({len(seen)} unique)</h3>'
        body += '<table><tr><th>Type</th><th>Value</th><th>Last seen</th><th>Sightings</th></tr>'
        for v, data in list(seen.items())[:30]:
            body += f'<tr><td>{data["ioc_type"]}</td><td><a href="/ioc-detail?value={esc(v)}"><code>{esc(v[:60])}</code></a></td><td>{esc(data["latest"][:16])}</td><td>{data["count"]}</td></tr>'
        body += '</table></div>'

    body += '<h3>Recent Messages</h3>'
    for m in messages:
        text_preview = esc((m.get("text") or "")[:300])
        fwd = f' ↩️ from {esc(m["forward_from"])}' if m.get("forward_from") else ""
        body += f"""<div class="card">
          <span class="meta">{esc(m['date'][:16])} · {esc(m['sender_name'])}{fwd}</span>
          <p>{text_preview}</p>
        </div>"""

    return web.Response(text=_page(chan["title"], body, csrf=csrf_field(req)), content_type="text/html")


async def h_search(req):
    q = req.query.get("q", "").strip()
    if not q:
        return web.Response(text=_page("Search", '<div class="empty">Enter a query above.</div>', q),
                            content_type="text/html")

    try:
        msg_results = await db.search_messages(q, limit=30)
    except Exception:
        msg_results = []
    try:
        ioc_results = await db.search_iocs(value=q, limit=20)
    except Exception:
        ioc_results = []

    body = ""
    if ioc_results:
        body += f'<h3>🔍 IOC matches for "{esc(q)}"</h3>'
        body += '<table><tr><th>IOC</th><th>Type</th><th>Channel</th><th>Seen</th></tr>'
        for i in ioc_results:
            body += f'<tr><td><a href="/ioc-detail?value={esc(i["value"])}"><code>{esc(i["value"][:50])}</code></a></td><td>{i["ioc_type"]}</td><td>{esc(i.get("channel_title",""))}</td><td>{esc(i["first_seen"][:16])}</td></tr>'
        body += '</table>'

    if msg_results:
        body += f'<h3>💬 Message matches ({len(msg_results)})</h3>'
        for r in msg_results:
            snippet = esc((r.get("snippet") or "")).replace("»", "<b>").replace("«", "</b>")
            body += f"""<div class="card">
              <b>{esc(r.get('channel_title',''))}</b> <span class="meta">{esc(r['date'][:16])} · {esc(r.get('sender_name',''))}</span>
              <div class="snippet">{snippet}</div>
            </div>"""

    if not msg_results and not ioc_results:
        body = f'<div class="empty">No results for <b>{esc(q)}</b>.</div>'

    return web.Response(text=_page("Search", body, q, csrf=csrf_field(req)), content_type="text/html")


async def h_iocs(req):
    ioc_type = req.query.get("type")
    value = req.query.get("value")
    summary = await db.get_ioc_summary()

    body = '<h2>Extracted IOCs</h2>'
    if summary:
        body += '<div class="tabs">'
        body += '<a href="/iocs" class="' + ('active' if not ioc_type else '') + '">All</a>'
        for s in summary:
            active = "active" if ioc_type == s["ioc_type"] else ""
            body += f'<a href="/iocs?type={s["ioc_type"]}" class="{active}">{s["ioc_type"]} ({s["unique_count"]})</a>'
        body += '</div>'

    iocs = await db.search_iocs(ioc_type=ioc_type, value=value, limit=100)
    if iocs:
        # Deduplicate by value — track first seen, last seen, and channels
        seen: dict[str, dict] = {}
        for i in iocs:
            v = i["value"]
            ts = i.get("first_seen", "")
            if v not in seen:
                seen[v] = {
                    "ioc_type": i["ioc_type"], "value": v,
                    "first_seen": ts, "last_seen": ts,
                    "channel_count": 1,
                    "channels": [i.get("channel_title", "")],
                    "latest_channel": i.get("channel_title", ""),
                }
            else:
                seen[v]["channel_count"] += 1
                ch = i.get("channel_title", "")
                if ch and ch not in seen[v]["channels"]:
                    seen[v]["channels"].append(ch)
                if ts and ts < seen[v]["first_seen"]:
                    seen[v]["first_seen"] = ts
                if ts and ts > seen[v]["last_seen"]:
                    seen[v]["last_seen"] = ts
                    seen[v]["latest_channel"] = ch

        body += '<table><tr><th>Value</th><th>Type</th><th>Last channel</th><th>First seen</th><th>Last seen</th></tr>'
        for v, i in seen.items():
            ch_display = i["latest_channel"]
            if len(i["channels"]) > 1:
                ch_display += f' <span style="color:var(--ac);font-size:10px">+{len(i["channels"]) - 1} more</span>'
            body += f'<tr><td><a href="/ioc-detail?value={esc(v)}"><code>{esc(v[:60])}</code></a></td><td>{i["ioc_type"]}</td><td>{ch_display}</td><td>{esc(i["first_seen"][:16])}</td><td>{esc(i["last_seen"][:16])}</td></tr>'
        body += '</table>'
    else:
        body += '<div class="empty">No IOCs extracted yet.</div>'

    return web.Response(text=_page("IOCs", body, csrf=csrf_field(req)), content_type="text/html")


async def h_ioc_detail(req):
    """IOC detail page — shows overall first/last seen, per-channel breakdown, and all sightings."""
    value = req.query.get("value", "").strip()
    if not value:
        raise web.HTTPFound("/iocs")

    sightings = await db.get_ioc_timeline(value)

    body = f'<h2>IOC: <code>{esc(value)}</code></h2>'

    if not sightings:
        body += '<div class="empty">No sightings found for this IOC.</div>'
    else:
        ioc_type = sightings[0].get("ioc_type", "unknown")

        # Calculate overall first/last seen
        all_dates = [s.get("date", "") for s in sightings if s.get("date")]
        overall_first = min(all_dates) if all_dates else ""
        overall_last = max(all_dates) if all_dates else ""

        # Per-channel breakdown
        channel_data: dict[str, dict] = {}
        for s in sightings:
            ch = s.get("channel_title", "") or "Unknown"
            d = s.get("date", "")
            if ch not in channel_data:
                channel_data[ch] = {"first_seen": d, "last_seen": d, "count": 1}
            else:
                channel_data[ch]["count"] += 1
                if d and d < channel_data[ch]["first_seen"]:
                    channel_data[ch]["first_seen"] = d
                if d and d > channel_data[ch]["last_seen"]:
                    channel_data[ch]["last_seen"] = d

        # Summary card
        body += '<div class="card">'
        body += f'<p style="font-size:12px"><b>Type:</b> {esc(ioc_type)}</p>'
        body += f'<p style="font-size:12px"><b>First seen (overall):</b> {esc(overall_first[:16])}</p>'
        body += f'<p style="font-size:12px"><b>Last seen (overall):</b> {esc(overall_last[:16])}</p>'
        body += f'<p style="font-size:12px"><b>Total sightings:</b> {len(sightings)}</p>'
        body += f'<p style="font-size:12px"><b>Channels:</b> {len(channel_data)}</p>'
        body += '</div>'

        # Per-channel table
        body += '<div class="card"><h3>Per-channel breakdown</h3>'
        body += '<table class="tb"><tr><th>Channel</th><th>First seen</th><th>Last seen</th><th>Sightings</th></tr>'
        for ch, data in channel_data.items():
            body += f'<tr><td>{esc(ch)}</td><td>{esc(data["first_seen"][:16])}</td><td>{esc(data["last_seen"][:16])}</td><td>{data["count"]}</td></tr>'
        body += '</table></div>'

        # Individual sightings
        body += '<h3 style="font-size:14px;font-weight:500;margin:14px 0 8px;font-family:var(--fn)">All sightings</h3>'
        for s in sightings:
            text_preview = esc((s.get("text") or "")[:200])
            body += f'''<div class="card">
              <b style="font-size:12px">{esc(s.get("channel_title",""))}</b>
              <span class="meta" style="margin-left:8px">{esc(s.get("date","")[:16])}</span>
              <p style="font-size:11px;color:var(--mt);margin-top:4px">{text_preview}</p>
            </div>'''

    return web.Response(text=_page(f"IOC {value[:30]}", body, csrf=csrf_field(req)), content_type="text/html")


async def h_alerts(req):
    alerts = await db.get_recent_alerts(100)
    body = '<h2>🚨 Alerts</h2>'
    if not alerts:
        body += '<div class="empty">No alerts fired yet. Add keywords via Settings.</div>'
    else:
        # Ack all button
        unack = [a for a in alerts if not a.get("acknowledged")]
        if unack:
            body += '''<form method="post" action="/alerts/ack-all" style="margin-bottom:10px">
              <button type="submit" style="padding:5px 14px;background:var(--ac);color:#000;border:none;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer">Acknowledge all ({count})</button>
            </form>'''.replace("{count}", str(len(unack)))

        body += '<table><tr><th>Time</th><th>Keyword</th><th>Channel</th><th>Snippet</th><th></th></tr>'
        for a in alerts:
            ack = "" if a["acknowledged"] else ' <span class="badge alert">NEW</span>'
            ack_btn = ""
            if not a.get("acknowledged"):
                ack_btn = f'''<form method="post" action="/alerts/ack" style="display:inline">
                  <input type="hidden" name="alert_id" value="{a['id']}">
                  <button type="submit" style="background:none;border:1px solid var(--bd);color:var(--mt);border-radius:4px;padding:2px 6px;font-size:10px;cursor:pointer">Ack</button>
                </form>'''
            body += f'<tr><td>{esc(a["fired_at"][:16])}{ack}</td><td><code>{esc(a["keyword"])}</code></td><td>{esc(a["channel_title"])}</td><td class="snippet">{esc(a["snippet"][:120])}</td><td>{ack_btn}</td></tr>'
        body += '</table>'
    return web.Response(text=_page("Alerts", body, csrf=csrf_field(req)), content_type="text/html")


async def h_stealer_logs(req):
    family = req.query.get("family")
    channel_id = req.query.get("channel_id")
    cid = int(channel_id) if channel_id else None

    stats = await db.get_stealer_log_stats()
    logs = await db.get_stealer_logs(channel_id=cid, family=family, limit=50)

    body = '<h2>Stealer logs</h2>'

    if stats.get("total", 0) > 0:
        body += f'<div class="card"><h3>Overview</h3><p style="font-size:12px;color:var(--text-secondary);margin:4px 0">Total detected: <b>{stats["total"]}</b></p>'
        if stats.get("by_family"):
            body += '<p style="font-size:12px;color:var(--text-secondary);margin:4px 0">By family: '
            body += ', '.join(f'{esc(f)} ({c})' for f, c in stats["by_family"].items())
            body += '</p>'
        if stats.get("by_channel"):
            body += '<p style="font-size:12px;color:var(--text-secondary);margin:4px 0">By channel: '
            body += ', '.join(f'{esc(ch)} ({c})' for ch, c in list(stats["by_channel"].items())[:8])
            body += '</p>'
        body += '</div>'

        body += '<div class="tabs">'
        body += f'<a href="/stealer-logs" class="{"active" if not family else ""}">All</a>'
        for f in stats.get("by_family", {}):
            active = "active" if family == f else ""
            body += f'<a href="/stealer-logs?family={esc(f)}" class="{active}">{esc(f)}</a>'
        body += '</div>'

    if not logs:
        body += '<div class="empty">No stealer logs detected yet. Monitor channels that post stealer log content.</div>'
    else:
        for log in logs:
            families = ", ".join(log.get("families", [])) or "unknown"
            countries = ", ".join(log.get("countries", [])[:8]) or ""
            dtypes = ", ".join(log.get("data_types", [])[:6]) or ""
            count = log.get("log_count")
            count_str = f"{count:,}" if count else ""
            price = log.get("price_usd") or ""
            conf = log.get("confidence", 0)
            has_dl = log.get("has_download", False)
            dl_type = log.get("download_type", "")

            dl_badge = ""
            if has_dl:
                dl_badge = f' <span class="badge on" style="margin-left:6px">📥 {esc(dl_type)}</span>'
            else:
                dl_badge = ' <span class="badge off" style="margin-left:6px">no download</span>'

            body += f'''<div class="card">
              <p style="font-size:12px;margin:0">
                <b>{esc(families)}</b>{dl_badge}
                <span style="color:var(--mt);font-size:11px;margin-left:8px">{esc(log.get("channel_title",""))}</span>
                <span style="color:var(--mt);font-size:11px;margin-left:8px">{esc(log.get("date","")[:16])}</span>
                <span style="color:var(--mt);font-size:10px;margin-left:8px">({int(conf*100)}%)</span>
              </p>
              <p style="font-size:11px;color:var(--mt);margin:4px 0">'''
            parts = []
            if count_str:
                parts.append(f'Count: <b>{count_str}</b>')
            if price:
                parts.append(f'Price: <b>${esc(price)}</b>')
            if countries:
                parts.append(f'Countries: {esc(countries)}')
            body += ' &nbsp; '.join(parts)
            body += f'''</p>'''
            if dtypes:
                body += f'<p style="font-size:11px;color:var(--mt);margin:2px 0">Data: {esc(dtypes)}</p>'
            body += f'''<p style="font-size:11px;color:var(--mt);margin:4px 0 0">{esc((log.get("message_text",""))[:200])}</p>
            </div>'''

    return web.Response(text=_page("Stealer logs", body, csrf=csrf_field(req)), content_type="text/html")


# ── JSON API ──────────────────────────────────────────────────────────

async def api_health(req):
    from health import get_tracker
    status = get_tracker().get_status()
    code = 200 if status["status"] in ("healthy", "waiting") else 503
    return web.json_response(status, status=code)

async def h_health(req):
    """Human-readable health page."""
    from health import get_tracker
    status = get_tracker().get_status()

    state = status["status"]
    color = {"healthy": "var(--gn)", "waiting": "var(--yl)",
             "stale": "var(--or)", "disconnected": "var(--rd)"}.get(state, "var(--mt)")

    body = f"""<h2>Health check</h2>
    <div class="card">
      <p><b>Status:</b> <span style="color:{color};font-weight:700">{state.upper()}</span></p>
      <p><b>Connected:</b> {'yes' if status['connected'] else 'no'}</p>
      <p><b>Uptime:</b> {esc(status['uptime_human'])}</p>
      <p><b>Last message:</b> {esc(str(status['last_message_at'] or 'none yet'))}</p>
      <p><b>Seconds since last message:</b> {status['seconds_since_last_message'] or 'n/a'}</p>
      <p><b>Messages total:</b> {status['messages_total']}</p>
      <p><b>Messages/min:</b> {status['messages_per_minute']}</p>
      <p><b>Stale threshold:</b> {status['stale_threshold_seconds']}s</p>
    </div>"""
    return web.Response(text=_page("Health", body, csrf=csrf_field(req)), content_type="text/html")

async def api_search(req):
    q = req.query.get("q", "")
    return web.json_response({"messages": await db.search_messages(q),
                               "iocs": await db.search_iocs(value=q)})

async def api_stats(req):
    return web.json_response(await db.get_stats())

async def api_export(req):
    return web.json_response(await db.export_all(), dumps=lambda o: json.dumps(o, default=str))

async def api_iocs(req):
    return web.json_response(await db.search_iocs(
        ioc_type=req.query.get("type"), value=req.query.get("value")))


# ══════════════════════════════════════════════════════════════════════
#  DISCOVERY
# ══════════════════════════════════════════════════════════════════════

async def h_discovery(req):
    """Discovery page: review auto-discovered channel candidates."""
    status_filter = req.query.get("status", "pending")
    candidates = await db.get_candidates(status=status_filter)
    counts = await db.get_candidate_counts()
    scanner_on = _scanner_available()

    body = '<h2>Channel discovery</h2>'

    if not config.DISCOVERY_KEYWORDS:
        body += '<div class="card"><p style="font-size:12px;color:var(--mt)">Auto-discovery is disabled. Add <code>DISCOVERY_KEYWORDS</code> to your .env file with comma-separated search terms, then restart.</p></div>'
    else:
        kw_list = ", ".join(f'<code>{esc(k)}</code>' for k in config.DISCOVERY_KEYWORDS)
        body += f'<div class="card"><p style="font-size:12px;color:var(--mt)">Searching every {config.DISCOVERY_INTERVAL // 3600}h for: {kw_list}</p></div>'

    # Status tabs
    pending = counts.get("pending", 0)
    approved = counts.get("approved", 0)
    dismissed = counts.get("dismissed", 0)
    body += '<div class="tabs">'
    body += f'<a href="/discovery?status=pending" class="{"active" if status_filter == "pending" else ""}">Pending ({pending})</a>'
    body += f'<a href="/discovery?status=approved" class="{"active" if status_filter == "approved" else ""}">Approved ({approved})</a>'
    body += f'<a href="/discovery?status=dismissed" class="{"active" if status_filter == "dismissed" else ""}">Dismissed ({dismissed})</a>'
    body += '</div>'

    if not candidates:
        body += f'<div class="empty">No {status_filter} candidates.</div>'
    else:
        for c in candidates:
            handle = f"@{c['username']}" if c.get("username") else ""
            body += f'''<div class="card">
              <h3 style="font-size:13px">{esc(c.get("title",""))}</h3>
              <p style="font-size:11px;color:var(--mt)">{esc(handle)} · {c.get("channel_type","")} · {c.get("participants",0)} members · found via "{esc(c.get("search_term",""))}"</p>'''
            if c.get("about"):
                body += f'<p style="font-size:11px;color:var(--mt);margin-top:4px">{esc(c["about"][:200])}</p>'

            if status_filter == "pending" and scanner_on:
                body += f'''<div style="margin-top:6px;display:flex;gap:6px">
                  <form method="post" action="/discovery/approve"><input type="hidden" name="channel_id" value="{c['channel_id']}">
                    <button type="submit" style="padding:4px 12px;background:var(--ac);color:#000;border:none;border-radius:4px;font-size:11px;font-weight:600;cursor:pointer">Approve &amp; monitor</button></form>
                  <form method="post" action="/discovery/dismiss"><input type="hidden" name="channel_id" value="{c['channel_id']}">
                    <button type="submit" style="padding:4px 12px;background:none;border:1px solid var(--rd);color:var(--rd);border-radius:4px;font-size:11px;cursor:pointer">Dismiss</button></form>
                </div>'''
            elif status_filter == "pending" and not scanner_on:
                body += '<p style="font-size:11px;color:var(--mt);margin-top:4px">Scanner must be running to approve.</p>'

            body += '</div>'

    return web.Response(text=_page("Discovery", body, csrf=csrf_field(req)), content_type="text/html")


async def h_discovery_approve(req):
    """POST: approve a candidate — join and monitor it."""
    data = await req.post()
    channel_id = data.get("channel_id", "")
    if channel_id and _scanner_available():
        try:
            cid = int(channel_id)
            # Get candidate info for the username/ID
            candidates = await db.get_candidates("pending")
            candidate = next((c for c in candidates if c["channel_id"] == cid), None)
            if candidate:
                target = candidate.get("username") or str(cid)
                await _call_scanner_async(_scanner.join_and_monitor, target)
                await db.set_candidate_status(cid, "approved")
        except Exception as e:
            logger.error("Discovery approve failed: %s", e)
    raise web.HTTPFound("/discovery")


async def h_discovery_dismiss(req):
    """POST: dismiss a candidate."""
    data = await req.post()
    channel_id = data.get("channel_id", "")
    if channel_id:
        try:
            await db.set_candidate_status(int(channel_id), "dismissed")
        except Exception:
            pass
    raise web.HTTPFound("/discovery")


# ══════════════════════════════════════════════════════════════════════
#  ALERT ACKNOWLEDGMENT
# ══════════════════════════════════════════════════════════════════════

async def h_ack_alert(req):
    """POST: acknowledge a single alert."""
    data = await req.post()
    alert_id = data.get("alert_id", "")
    if alert_id:
        try:
            await db.acknowledge_alert(int(alert_id))
        except Exception:
            pass
    referer = req.headers.get("Referer", "/alerts")
    raise web.HTTPFound(referer)


async def h_ack_all_alerts(req):
    """POST: acknowledge all unread alerts."""
    alerts = await db.get_recent_alerts(limit=500, unack_only=True)
    for a in alerts:
        try:
            await db.acknowledge_alert(a["id"])
        except Exception:
            pass
    referer = req.headers.get("Referer", "/alerts")
    raise web.HTTPFound(referer)


# ══════════════════════════════════════════════════════════════════════
#  SETTINGS / MANAGEMENT
# ══════════════════════════════════════════════════════════════════════

async def h_settings(req):
    """Settings page with tabbed sections."""
    tab = req.query.get("tab", "general")
    scanner_on = _scanner_available()
    bot_on = bool(config.BOT_TOKEN)

    # Tab navigation
    tabs = [("general", "General"), ("channels", "Channels"),
            ("keywords", "Keywords"), ("filters", "Filters"),
            ("notifications", "Notifications")]

    body = '<h2>Settings</h2>'
    body += '<div class="tabs" style="margin-bottom:14px">'
    for tid, label in tabs:
        active = "active" if tab == tid else ""
        body += f'<a href="/settings?tab={tid}" class="{active}">{label}</a>'
    body += '</div>'

    # ══════════════════════════════════════════════════════════════════
    #  GENERAL TAB
    # ══════════════════════════════════════════════════════════════════
    if tab == "general":
        body += '<div class="card"><h3>Scanner status</h3>'
        if scanner_on:
            body += '<p style="font-size:12px;color:var(--gn)">Scanner is running.</p>'
        else:
            body += '<p style="font-size:12px;color:var(--mt)">Scanner is not running (web-only mode).</p>'
        body += f'<p style="font-size:12px;color:var(--mt);margin-top:4px">Companion bot: {"enabled" if bot_on else "disabled"}</p>'
        body += '</div>'

        # Backfill limit
        bl = await db.get_setting("backfill_limit", str(config.BACKFILL_LIMIT))
        body += f'''<div class="card"><h3>Backfill</h3>
          <form method="post" action="/settings/update-general" style="display:flex;gap:6px;align-items:center;margin-top:6px">
            <label style="font-size:12px">Messages to pull on join/backfill:</label>
            <input name="backfill_limit" value="{esc(bl)}" style="width:80px;padding:4px 6px;border:1px solid var(--bd);border-radius:4px;background:var(--bg);color:var(--tx);font-size:12px">
            <button type="submit" style="padding:4px 12px;background:var(--ac);color:#000;border:none;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer">Save</button>
          </form></div>'''

        # Data management
        body += '<div class="card"><h3>Data management</h3>'
        body += '<p style="font-size:12px;color:var(--mt)">Use <code>python reset_data.py</code> to clear collected data while keeping channels and keywords.</p>'
        body += '<p style="font-size:12px;color:var(--mt)">Use <code>python migrate.py</code> after updating to add new database tables.</p>'
        body += '</div>'

    # ══════════════════════════════════════════════════════════════════
    #  CHANNELS TAB
    # ══════════════════════════════════════════════════════════════════
    elif tab == "channels":
        # Search
        body += '<div class="card"><h3>Search Telegram channels</h3>'
        if scanner_on:
            body += '''<form style="display:flex;gap:6px;margin-top:6px" method="post" action="/settings/search-channels">
              <input name="q" placeholder="e.g. redline logs, ransomware leak …"
               style="flex:1;padding:6px 8px;border:1px solid var(--bd);border-radius:6px;background:var(--bg);color:var(--tx);font-size:12px;font-family:var(--mo)">
              <button type="submit" style="padding:6px 14px;background:var(--ac);color:#000;border:none;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer">Search</button>
            </form>'''
        else:
            body += '<p style="font-size:12px;color:var(--mt)">Scanner must be running to search.</p>'
        body += '</div>'

        # Add by handle
        body += '<div class="card"><h3>Add channel by @handle or link</h3>'
        if scanner_on:
            body += '''<form style="display:flex;gap:6px;margin-top:6px" method="post" action="/settings/add-channel">
              <input name="channel" placeholder="@channel, https://t.me/channel, or channel ID"
               style="flex:1;padding:6px 8px;border:1px solid var(--bd);border-radius:6px;background:var(--bg);color:var(--tx);font-size:12px;font-family:var(--mo)">
              <button type="submit" style="padding:6px 14px;background:var(--ac);color:#000;border:none;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer">Join &amp; monitor</button>
            </form>'''
        else:
            body += '<p style="font-size:12px;color:var(--mt)">Scanner must be running to add channels.</p>'
        body += '</div>'

        # Channel list
        channels = await db.get_all_channels()
        if channels:
            body += '<div class="card"><h3>Monitored channels</h3>'
            body += '<table class="tb"><tr><th>Channel</th><th>Type</th><th>Members</th><th>Status</th><th></th></tr>'
            for c in channels:
                status = '<span class="badge on">ON</span>' if c["is_monitored"] else '<span class="badge off">OFF</span>'
                title_link = f'<a href="/channel/{c["id"]}">{esc(c["title"])}</a>'
                if c["username"]:
                    title_link += f' <span style="color:var(--mt);font-size:10px">@{esc(c["username"])}</span>'
                if c["is_monitored"] and scanner_on:
                    action = f'''<form method="post" action="/settings/unmonitor" style="display:inline">
                      <input type="hidden" name="channel_id" value="{c['id']}">
                      <button type="submit" style="background:none;border:1px solid var(--rd);color:var(--rd);border-radius:4px;padding:2px 8px;font-size:10px;cursor:pointer">Stop</button>
                    </form>
                    <form method="post" action="/settings/backfill" style="display:inline;margin-left:4px">
                      <input type="hidden" name="channel_id" value="{c['id']}">
                      <button type="submit" style="background:none;border:1px solid var(--ac);color:var(--ac);border-radius:4px;padding:2px 8px;font-size:10px;cursor:pointer">Backfill</button>
                    </form>'''
                elif not c["is_monitored"] and scanner_on:
                    action = f'''<form method="post" action="/settings/remonitor" style="display:inline">
                      <input type="hidden" name="channel_id" value="{c['id']}">
                      <button type="submit" style="background:none;border:1px solid var(--gn);color:var(--gn);border-radius:4px;padding:2px 8px;font-size:10px;cursor:pointer">Resume</button>
                    </form>'''
                else:
                    action = ''
                body += f'<tr><td>{title_link}</td><td>{c["channel_type"]}</td><td>{c["participants"]}</td><td>{status}</td><td>{action}</td></tr>'
            body += '</table></div>'

    # ══════════════════════════════════════════════════════════════════
    #  KEYWORDS TAB
    # ══════════════════════════════════════════════════════════════════
    elif tab == "keywords":
        keywords = await db.get_alert_keywords()
        body += '<div class="card"><h3>Alert keywords</h3>'
        body += '<p style="font-size:11px;color:var(--mt);margin-bottom:6px">Messages matching these trigger alerts and ntfy notifications.</p>'
        body += '''<form style="display:flex;gap:6px;margin-top:6px" method="post" action="/settings/add-keyword?tab=keywords">
          <input name="keyword" placeholder="Add keyword …"
           style="flex:1;padding:6px 8px;border:1px solid var(--bd);border-radius:6px;background:var(--bg);color:var(--tx);font-size:12px;font-family:var(--mo)">
          <select name="is_regex" style="padding:6px;border:1px solid var(--bd);border-radius:6px;background:var(--bg);color:var(--tx);font-size:11px">
            <option value="0">Keyword</option><option value="1">Regex</option></select>
          <button type="submit" style="padding:6px 14px;background:var(--ac);color:#000;border:none;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer">Add</button>
        </form>'''
        if keywords:
            body += '<table class="tb" style="margin-top:8px"><tr><th>Keyword</th><th>Type</th><th></th></tr>'
            for kw in keywords:
                mode = "regex" if kw.get("is_regex") else "keyword"
                body += f'''<tr><td><code>{esc(kw["keyword"])}</code></td><td>{mode}</td><td>
                  <form method="post" action="/settings/remove-keyword?tab=keywords" style="display:inline">
                    <input type="hidden" name="keyword" value="{esc(kw['keyword'])}">
                    <button type="submit" style="background:none;border:1px solid var(--rd);color:var(--rd);border-radius:4px;padding:2px 8px;font-size:10px;cursor:pointer">Remove</button>
                  </form></td></tr>'''
            body += '</table>'
        else:
            body += '<p style="font-size:12px;color:var(--mt);margin-top:6px">No keywords configured.</p>'
        body += '</div>'

    # ══════════════════════════════════════════════════════════════════
    #  FILTERS TAB
    # ══════════════════════════════════════════════════════════════════
    elif tab == "filters":
        from filters import get_filter_status
        fs = get_filter_status()

        body += '<div class="card"><h3>Filter toggles</h3>'
        body += '<p style="font-size:11px;color:var(--mt);margin-bottom:8px">Changes take effect immediately.</p>'

        def _toggle(key, label, desc, checked):
            return f'''<tr><td style="width:40px">
              <form method="post" action="/settings/toggle-filter" style="display:inline">
                <input type="hidden" name="key" value="{key}">
                <input type="hidden" name="value" value="{'false' if checked else 'true'}">
                <button type="submit" style="background:{'var(--gn)' if checked else 'var(--bd)'};color:{'#000' if checked else 'var(--mt)'};border:none;border-radius:4px;padding:3px 10px;font-size:11px;font-weight:600;cursor:pointer">{'ON' if checked else 'OFF'}</button>
              </form></td>
              <td><b>{label}</b></td><td style="color:var(--mt);font-size:11px">{desc}</td></tr>'''

        body += '<table class="tb">'
        body += _toggle("filter_enabled", "Master filter", "Turn all filtering on/off. Off = store everything.", fs["enabled"])
        body += _toggle("filter_relevance_only", "Relevance only", "Only store messages with IOCs, keyword matches, or stealer log content.", fs["relevance_only"])
        body += _toggle("filter_spam_enabled", "Spam filter", f'{fs["spam_patterns"]} built-in patterns (VIP bait, fake giveaways).', fs["spam_enabled"])
        body += _toggle("filter_skip_private_ips", "Skip private IPs", "Drop 10.x, 172.16-31.x, 192.168.x, 127.x.", fs["skip_private_ips"])
        body += _toggle("filter_stealer_require_download", "Stealer: require download", "Only keep stealer logs with a download link.", fs["stealer_require_download"])
        body += '</table></div>'

        body += f'''<div class="card"><h3>Filter values</h3>
          <form method="post" action="/settings/update-filters">
            <table class="tb">
              <tr><td><b>Min message length</b></td><td><input name="filter_min_msg_length" value="{fs['min_message_length']}" style="width:60px;padding:3px 6px;border:1px solid var(--bd);border-radius:4px;background:var(--bg);color:var(--tx);font-size:12px"></td><td style="color:var(--mt);font-size:11px">Shorter messages are discarded</td></tr>
              <tr><td><b>Stealer min confidence</b></td><td><input name="filter_stealer_min_confidence" value="{fs['stealer_min_confidence']}" style="width:60px;padding:3px 6px;border:1px solid var(--bd);border-radius:4px;background:var(--bg);color:var(--tx);font-size:12px"></td><td style="color:var(--mt);font-size:11px">0.0 to 1.0</td></tr>
              <tr><td><b>IOC types</b></td><td colspan="2"><input name="filter_ioc_types" value="{', '.join(fs['allowed_ioc_types']) if fs['allowed_ioc_types'] != ['all'] else ''}" placeholder="empty = all" style="width:100%;padding:3px 6px;border:1px solid var(--bd);border-radius:4px;background:var(--bg);color:var(--tx);font-size:12px"><br><span style="font-size:10px;color:var(--mt)">ipv4, ipv6, domain, url, md5, sha1, sha256, email, cve, onion, btc, eth, xmr</span></td></tr>
              <tr><td><b>Ignore domains</b></td><td colspan="2"><input name="filter_ignore_domains" value="{fs['extra_ignore_domains']}" placeholder="example.com, test.com" style="width:100%;padding:3px 6px;border:1px solid var(--bd);border-radius:4px;background:var(--bg);color:var(--tx);font-size:12px"></td></tr>
            </table>
            <button type="submit" style="margin-top:8px;padding:5px 14px;background:var(--ac);color:#000;border:none;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer">Save</button>
          </form></div>'''

    # ══════════════════════════════════════════════════════════════════
    #  NOTIFICATIONS TAB
    # ══════════════════════════════════════════════════════════════════
    elif tab == "notifications":
        ntfy_enabled = await db.get_setting("ntfy_enabled", "false")
        ntfy_url = await db.get_setting("ntfy_url", "")
        ntfy_topic = await db.get_setting("ntfy_topic", "cti-alerts")
        ntfy_token = await db.get_setting("ntfy_token", "")
        ntfy_priority_alert = await db.get_setting("ntfy_priority_alert", "4")
        ntfy_priority_health = await db.get_setting("ntfy_priority_health", "5")
        is_on = ntfy_enabled.lower() in ("true", "1", "yes")

        # Detect source
        env_url = getattr(config, "NTFY_URL", "")
        if ntfy_url:
            source_msg = "Configured from settings."
        elif env_url:
            source_msg = "Detected from .env — values will be imported on next scanner restart."
        else:
            source_msg = "Not configured."

        body += '<div class="card"><h3>ntfy push notifications</h3>'
        body += f'<p style="font-size:11px;color:var(--mt);margin-bottom:4px">{source_msg}</p>'
        body += '<p style="font-size:11px;color:var(--mt);margin-bottom:8px">Sends alerts, health warnings, and retention summaries to your ntfy server. <a href="https://ntfy.sh" target="_blank">What is ntfy?</a></p>'

        # Enable toggle
        body += f'''<form method="post" action="/settings/toggle-ntfy" style="margin-bottom:10px">
          <input type="hidden" name="value" value="{'false' if is_on else 'true'}">
          <button type="submit" style="background:{'var(--gn)' if is_on else 'var(--bd)'};color:{'#000' if is_on else 'var(--mt)'};border:none;border-radius:6px;padding:5px 14px;font-size:12px;font-weight:600;cursor:pointer">{'Enabled' if is_on else 'Disabled'}</button>
        </form>'''

        # Config form
        body += f'''<form method="post" action="/settings/update-ntfy">
          <table class="tb">
            <tr><td style="width:130px"><b>Server URL</b></td><td><input name="ntfy_url" value="{esc(ntfy_url)}" placeholder="https://ntfy.example.com or http://ntfy:80" style="width:100%;padding:4px 6px;border:1px solid var(--bd);border-radius:4px;background:var(--bg);color:var(--tx);font-size:12px"></td></tr>
            <tr><td><b>Topic</b></td><td><input name="ntfy_topic" value="{esc(ntfy_topic)}" placeholder="cti-alerts" style="width:100%;padding:4px 6px;border:1px solid var(--bd);border-radius:4px;background:var(--bg);color:var(--tx);font-size:12px"></td></tr>
            <tr><td><b>Access token</b></td><td><input name="ntfy_token" value="{esc(ntfy_token)}" placeholder="tk_... (leave blank if no auth)" type="password" style="width:100%;padding:4px 6px;border:1px solid var(--bd);border-radius:4px;background:var(--bg);color:var(--tx);font-size:12px"></td></tr>
            <tr><td><b>Alert priority</b></td><td><select name="ntfy_priority_alert" style="padding:4px 6px;border:1px solid var(--bd);border-radius:4px;background:var(--bg);color:var(--tx);font-size:12px">
              {''.join(f'<option value="{i}" {"selected" if str(i) == ntfy_priority_alert else ""}>{["","Min","Low","Default","High","Urgent"][i]}</option>' for i in range(1,6))}
            </select></td></tr>
            <tr><td><b>Health priority</b></td><td><select name="ntfy_priority_health" style="padding:4px 6px;border:1px solid var(--bd);border-radius:4px;background:var(--bg);color:var(--tx);font-size:12px">
              {''.join(f'<option value="{i}" {"selected" if str(i) == ntfy_priority_health else ""}>{["","Min","Low","Default","High","Urgent"][i]}</option>' for i in range(1,6))}
            </select></td></tr>
          </table>
          <div style="display:flex;gap:8px;margin-top:10px">
            <button type="submit" style="padding:5px 14px;background:var(--ac);color:#000;border:none;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer">Save</button>
          </div>
        </form>'''

        # Test button (separate form)
        body += '''<form method="post" action="/settings/test-ntfy" style="margin-top:10px">
          <button type="submit" style="padding:5px 14px;background:none;border:1px solid var(--ac);color:var(--ac);border-radius:6px;font-size:12px;font-weight:600;cursor:pointer">Send test notification</button>
        </form>'''
        body += '</div>'

        # Setup instructions
        body += '''<div class="card"><h3>Setup guide</h3>
          <p style="font-size:12px;color:var(--mt);line-height:1.6">
            <b>Self-hosted ntfy:</b> Set the URL to your server (e.g. <code>https://ntfy.example.com</code>).
            If the scanner and ntfy are on the same Docker network, use the container name
            (e.g. <code>http://ntfy:80</code>) to skip Traefik.<br><br>
            <b>ntfy.sh (free hosted):</b> Set URL to <code>https://ntfy.sh</code> and pick a unique
            topic name. No token needed for public topics.<br><br>
            <b>Token auth:</b> If your ntfy server requires authentication, create a user and token:<br>
            <code>docker exec -it ntfy sh</code><br>
            <code>ntfy user add cti-scanner</code><br>
            <code>ntfy access cti-scanner YOUR_TOPIC rw</code><br>
            <code>ntfy token add cti-scanner</code><br>
            Copy the <code>tk_...</code> token into the field above.<br><br>
            <b>Phone app:</b> Install the ntfy app (Android/iOS), add your server, and subscribe to your topic.
          </p></div>'''

    return web.Response(text=_page("Settings", body, csrf=csrf_field(req)), content_type="text/html")


async def h_search_channels(req):
    """POST: search Telegram for channels."""
    data = await req.post()
    query = data.get("q", "").strip()
    if not query or not _scanner_available():
        raise web.HTTPFound("/settings?tab=channels")

    try:
        results = await _call_scanner_async(_scanner.search_channels, query)
    except Exception as e:
        logger.error("Channel search failed for '%s': %s", query, e)
        results = []

    body = f'<h2>Channel search: "{esc(query)}"</h2>'
    body += f'<p style="font-size:12px;margin-bottom:12px"><a href="/settings">&larr; Back to settings</a></p>'

    if not results:
        body += f'<div class="empty">No channels found for "{esc(query)}".</div>'
    else:
        for r in results:
            handle = f"@{r['username']}" if r.get("username") else f"ID:{r['id']}"
            body += f'''<div class="card">
              <h3 style="font-size:13px">{esc(r.get("title",""))}</h3>
              <p style="font-size:11px;color:var(--mt)">{esc(handle)} &middot; {r.get("type","")} &middot; {r.get("participants",0)} members</p>
              <form method="post" action="/settings/add-channel" style="margin-top:6px">
                <input type="hidden" name="channel" value="{esc(r.get('username','') or str(r.get('id','')))}">
                <button type="submit" style="padding:4px 12px;background:var(--ac);color:#000;border:none;border-radius:4px;font-size:11px;font-weight:600;cursor:pointer">Join &amp; monitor</button>
              </form>
            </div>'''

    return web.Response(text=_page("Channel search", body, csrf=csrf_field(req)), content_type="text/html")


async def h_add_channel(req):
    """POST: join and monitor a channel."""
    data = await req.post()
    channel = data.get("channel", "").strip()
    if not channel or not _scanner_available():
        raise web.HTTPFound("/settings?tab=channels")

    try:
        result = await _call_scanner_async(_scanner.join_and_monitor, channel)
        if result:
            raise web.HTTPFound(f"/channel/{result['id']}")
    except web.HTTPFound:
        raise
    except Exception as e:
        logger.error("Failed to add channel '%s': %s", channel, e)

    raise web.HTTPFound("/settings?tab=channels")


async def h_unmonitor(req):
    """POST: stop monitoring a channel."""
    data = await req.post()
    channel_id = data.get("channel_id", "")
    if channel_id:
        try:
            cid = int(channel_id)
            if _scanner_available():
                await _call_scanner_async(_scanner.unmonitor, cid)
            else:
                await db.set_monitored(cid, False)
        except (ValueError, Exception):
            pass
    raise web.HTTPFound("/settings?tab=channels")


async def h_remonitor(req):
    """POST: resume monitoring a channel."""
    data = await req.post()
    channel_id = data.get("channel_id", "")
    if channel_id:
        try:
            cid = int(channel_id)
            await db.set_monitored(cid, True)
        except (ValueError, Exception):
            pass
    raise web.HTTPFound("/settings?tab=channels")


async def h_backfill(req):
    """POST: force a backfill on a channel."""
    data = await req.post()
    channel_id = data.get("channel_id", "")
    if channel_id and _scanner_available():
        try:
            cid = int(channel_id)
            await _call_scanner_async(_scanner._backfill_channel, cid)
        except Exception as e:
            logger.error("Backfill failed for %s: %s", channel_id, e)
    raise web.HTTPFound("/settings?tab=channels")


async def h_add_keyword(req):
    """POST: add an alert keyword."""
    data = await req.post()
    keyword = data.get("keyword", "").strip()
    is_regex = data.get("is_regex", "0") == "1"
    if keyword:
        await db.add_alert_keyword(keyword, is_regex)
        # Reload keywords in scanner if running
        if _scanner_available():
            try:
                await _call_scanner_async(_scanner._reload_keywords)
            except Exception:
                pass
    raise web.HTTPFound("/settings?tab=keywords")


async def h_remove_keyword(req):
    """POST: remove an alert keyword."""
    data = await req.post()
    keyword = data.get("keyword", "").strip()
    if keyword:
        await db.remove_alert_keyword(keyword)
        if _scanner_available():
            try:
                await _call_scanner_async(_scanner._reload_keywords)
            except Exception:
                pass
    raise web.HTTPFound("/settings?tab=keywords")


async def h_toggle_filter(req):
    """POST: toggle a boolean filter setting."""
    data = await req.post()
    key = data.get("key", "")
    value = data.get("value", "")
    if key and key.startswith("filter_"):
        await db.set_setting(key, value)
        await f.load_from_db()
    raise web.HTTPFound("/settings?tab=filters")


async def h_update_filters(req):
    """POST: save editable filter values."""
    data = await req.post()
    for key in ("filter_min_msg_length", "filter_stealer_min_confidence",
                "filter_ioc_types", "filter_ignore_domains"):
        val = data.get(key, "")
        await db.set_setting(key, val.strip())
    await f.load_from_db()
    raise web.HTTPFound("/settings?tab=filters")


async def h_update_general(req):
    """POST: save general settings."""
    data = await req.post()
    bl = data.get("backfill_limit", "500")
    await db.set_setting("backfill_limit", bl.strip())
    raise web.HTTPFound("/settings?tab=general")


async def h_toggle_ntfy(req):
    """POST: toggle ntfy on/off."""
    data = await req.post()
    await db.set_setting("ntfy_enabled", data.get("value", "false"))
    raise web.HTTPFound("/settings?tab=notifications")


async def h_update_ntfy(req):
    """POST: save ntfy configuration."""
    data = await req.post()
    for key in ("ntfy_url", "ntfy_topic", "ntfy_token",
                "ntfy_priority_alert", "ntfy_priority_health"):
        val = data.get(key, "")
        await db.set_setting(key, val.strip())
    raise web.HTTPFound("/settings?tab=notifications")


async def h_test_ntfy(req):
    """POST: send a test notification to ntfy."""
    import notify
    # Reload config from DB
    ntfy_enabled = await db.get_setting("ntfy_enabled", "false")
    ntfy_url = await db.get_setting("ntfy_url", "")
    ntfy_topic = await db.get_setting("ntfy_topic", "")
    ntfy_token = await db.get_setting("ntfy_token", "")

    if ntfy_enabled.lower() not in ("true", "1", "yes") or not ntfy_url or not ntfy_topic:
        raise web.HTTPFound("/settings?tab=notifications")

    # Send test directly using the DB values
    import httpx
    url = f"{ntfy_url.rstrip('/')}/{ntfy_topic}"
    headers = {"Title": "CTI Scanner: test notification",
               "Priority": "3", "Tags": "white_check_mark"}
    if ntfy_token:
        headers["Authorization"] = f"Bearer {ntfy_token}"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, content="If you see this, ntfy is configured correctly.",
                                     headers=headers)
            logger.info("ntfy test: %d %s", resp.status_code, resp.text[:100])
    except Exception as e:
        logger.error("ntfy test failed: %s", e)

    raise web.HTTPFound("/settings?tab=notifications")


async def _call_scanner_async(coro_func, *args, **kwargs):
    """Call a scanner coroutine from the web's event loop without blocking."""
    if not _scanner:
        return None
    scanner_loop = getattr(_scanner, '_loop', None)
    if not scanner_loop:
        return None
    future = asyncio.run_coroutine_threadsafe(coro_func(*args, **kwargs), scanner_loop)
    # Wait in a thread so we don't block the web event loop
    web_loop = asyncio.get_event_loop()
    return await web_loop.run_in_executor(None, future.result, 30)


# ══════════════════════════════════════════════════════════════════════
#  APP SETUP
# ══════════════════════════════════════════════════════════════════════

def create_app() -> web.Application:
    app = web.Application(middlewares=[csrf_middleware])
    app.router.add_get("/", h_dashboard)
    app.router.add_get("/channels", h_channels)
    app.router.add_get("/channel/{id}", h_channel_detail)
    app.router.add_get("/search", h_search)
    app.router.add_get("/iocs", h_iocs)
    app.router.add_get("/ioc-detail", h_ioc_detail)
    app.router.add_get("/alerts", h_alerts)
    app.router.add_get("/stealer-logs", h_stealer_logs)
    app.router.add_get("/health", h_health)
    app.router.add_get("/settings", h_settings)
    app.router.add_get("/api/health", api_health)
    app.router.add_get("/api/search", api_search)
    app.router.add_get("/api/stats", api_stats)
    app.router.add_get("/api/export", api_export)
    app.router.add_get("/api/iocs", api_iocs)
    # Management POST routes
    app.router.add_post("/settings/search-channels", h_search_channels)
    app.router.add_post("/settings/add-channel", h_add_channel)
    app.router.add_post("/settings/unmonitor", h_unmonitor)
    app.router.add_post("/settings/remonitor", h_remonitor)
    app.router.add_post("/settings/backfill", h_backfill)
    app.router.add_post("/settings/add-keyword", h_add_keyword)
    app.router.add_post("/settings/remove-keyword", h_remove_keyword)
    app.router.add_post("/settings/toggle-filter", h_toggle_filter)
    app.router.add_post("/settings/update-filters", h_update_filters)
    app.router.add_post("/settings/update-general", h_update_general)
    app.router.add_post("/settings/toggle-ntfy", h_toggle_ntfy)
    app.router.add_post("/settings/update-ntfy", h_update_ntfy)
    app.router.add_post("/settings/test-ntfy", h_test_ntfy)
    # Discovery routes
    app.router.add_get("/discovery", h_discovery)
    app.router.add_post("/discovery/approve", h_discovery_approve)
    app.router.add_post("/discovery/dismiss", h_discovery_dismiss)
    # Alert acknowledgment
    app.router.add_post("/alerts/ack", h_ack_alert)
    app.router.add_post("/alerts/ack-all", h_ack_all_alerts)

    async def on_startup(a):
        await db.init()
    app.on_startup.append(on_startup)
    return app


def start_web_background(scanner=None):
    if scanner:
        set_scanner(scanner)
    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        app = create_app()
        runner = web.AppRunner(app)
        loop.run_until_complete(runner.setup())
        site = web.TCPSite(runner, config.WEB_HOST, config.WEB_PORT)
        loop.run_until_complete(site.start())
        logger.info("🌐 Web UI at http://%s:%s", config.WEB_HOST, config.WEB_PORT)
        loop.run_forever()
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    web.run_app(create_app(), host=config.WEB_HOST, port=config.WEB_PORT)
