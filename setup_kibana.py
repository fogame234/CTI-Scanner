#!/usr/bin/env python3
"""
Set up Kibana data views (index patterns) and a starter dashboard.
Run once after docker compose up:

    python setup_kibana.py
"""

import json
import sys
import httpx

KIBANA_URL = "http://localhost:5601"
ES_URL = "http://localhost:9200"
PREFIX = "cti"

DATA_VIEWS = [
    {
        "name": "CTI Messages",
        "title": f"{PREFIX}-messages",
        "timeFieldName": "date",
    },
    {
        "name": "CTI IOCs",
        "title": f"{PREFIX}-iocs",
        "timeFieldName": "first_seen",
    },
    {
        "name": "CTI Alerts",
        "title": f"{PREFIX}-alerts",
        "timeFieldName": "fired_at",
    },
    {
        "name": "CTI Channels",
        "title": f"{PREFIX}-channels",
        "timeFieldName": "added_at",
    },
]


def create_data_views():
    """Create Kibana data views (index patterns)."""
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    created = 0

    for dv in DATA_VIEWS:
        payload = {
            "data_view": {
                "title": dv["title"],
                "name": dv["name"],
                "timeFieldName": dv.get("timeFieldName", ""),
            }
        }
        resp = httpx.post(
            f"{KIBANA_URL}/api/data_views/data_view",
            headers=headers,
            json=payload,
        )
        if resp.status_code in (200, 201):
            print(f"  ✅ Created data view: {dv['name']}")
            created += 1
        elif resp.status_code == 409:
            print(f"  ℹ️  Already exists: {dv['name']}")
        else:
            print(f"  ❌ Failed: {dv['name']} — {resp.status_code} {resp.text[:200]}")

    return created


def check_connectivity():
    """Verify ES and Kibana are reachable."""
    try:
        r = httpx.get(f"{ES_URL}/_cluster/health", timeout=5)
        status = r.json().get("status", "unknown")
        print(f"  ES cluster health: {status}")
    except Exception as e:
        print(f"  ❌ Cannot reach Elasticsearch at {ES_URL}: {e}")
        sys.exit(1)

    try:
        r = httpx.get(f"{KIBANA_URL}/api/status", timeout=10)
        state = r.json().get("status", {}).get("overall", {}).get("level", "unknown")
        print(f"  Kibana status: {state}")
    except Exception as e:
        print(f"  ❌ Cannot reach Kibana at {KIBANA_URL}: {e}")
        sys.exit(1)


def main():
    print("\n🛡️  CTI Scanner — Kibana Setup\n")
    print("Checking connectivity …")
    check_connectivity()
    print("\nCreating data views …")
    create_data_views()
    print(f"\n✅ Done. Open Kibana at {KIBANA_URL}")
    print("   → Analytics > Discover to browse messages and IOCs")
    print("   → Analytics > Dashboard to build visualizations")
    print("\nSuggested first dashboard panels:")
    print("  1. Messages over time (date histogram on cti-messages)")
    print("  2. IOC type breakdown (pie chart on cti-iocs, split by ioc_type)")
    print("  3. Top IOC values (data table on cti-iocs, terms agg on value)")
    print("  4. Alert timeline (date histogram on cti-alerts)")
    print("  5. Channel message volume (bar chart, terms agg on channel_title.keyword)")


if __name__ == "__main__":
    main()
