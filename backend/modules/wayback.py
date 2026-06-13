import requests
from datetime import datetime


def check_availability(domain: str) -> dict:
    """
    Checks if the Wayback Machine has ANY snapshot of this domain.

    The Wayback Machine API endpoint:
    https://archive.org/wayback/available?url=DOMAIN

    This is the fastest check — just tells you yes/no and
    gives you the closest available snapshot URL.

    Returns dict with:
      - available    : True/False
      - snapshot_url : direct URL to view the archived page
      - timestamp    : when the snapshot was taken
      - status       : HTTP status of the archived page
    """
    url = "https://archive.org/wayback/available"
    params = {"url": domain}

    try:
        response = requests.get(url, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()

        snapshot = data.get("archived_snapshots", {}).get("closest", {})

        if not snapshot or not snapshot.get("available"):
            return {
                "available": False,
                "snapshot_url": None,
                "timestamp": None,
                "status": None,
            }

        # Convert timestamp from "20240115103045" → "2024-01-15"
        raw_ts = snapshot.get("timestamp", "")
        formatted_ts = None
        if len(raw_ts) >= 8:
            try:
                formatted_ts = datetime.strptime(
                    raw_ts[:8], "%Y%m%d"
                ).strftime("%Y-%m-%d")
            except ValueError:
                formatted_ts = raw_ts

        return {
            "available": True,
            "snapshot_url": snapshot.get("url"),
            "timestamp": formatted_ts,
            "status": snapshot.get("status"),
        }

    except requests.exceptions.Timeout:
        print(f"[wayback] Timeout for {domain}")
        return {"available": False, "snapshot_url": None,
                "timestamp": None, "status": None}
    except Exception as e:
        print(f"[wayback] Error: {e}")
        return {"available": False, "snapshot_url": None,
                "timestamp": None, "status": None}


def get_all_snapshots(domain: str, limit: int = 10) -> list:
    """
    Fetches a list of ALL historical snapshots for a domain
    using the CDX API — a more powerful Wayback Machine endpoint.

    CDX API: https://web.archive.org/cdx/search/cdx
    Free, no key needed, very powerful.

    Why multiple snapshots matter:
    A scam site might have changed its appearance over time —
    different promises at different stages. Seeing the full
    snapshot history tells investigators:
      - When did the site first appear?
      - When did it go offline?
      - How many times was it crawled (= how active was it)?

    Returns list of snapshot dicts:
      - timestamp   : human-readable date
      - url         : archived URL for this snapshot
      - status_code : HTTP status at time of crawl (200=live, 404=dead)
      - mime_type   : content type
    """
    cdx_url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": domain,
        "output": "json",
        "limit": limit,
        "fl": "timestamp,original,statuscode,mimetype",
        "collapse": "timestamp:8",   # one snapshot per day max
        "filter": "statuscode:200",  # only successful crawls
    }

    try:
        response = requests.get(cdx_url, params=params, timeout=15)
        response.raise_for_status()
        raw = response.json()

        if not raw or len(raw) < 2:
            return []

        # First row is headers, rest is data
        headers = raw[0]
        rows = raw[1:]

        snapshots = []
        for row in rows:
            record = dict(zip(headers, row))
            raw_ts = record.get("timestamp", "")

            # Format timestamp
            try:
                formatted = datetime.strptime(
                    raw_ts[:8], "%Y%m%d"
                ).strftime("%Y-%m-%d")
            except (ValueError, TypeError):
                formatted = raw_ts

            snapshots.append({
                "timestamp": formatted,
                "url": f"https://web.archive.org/web/{raw_ts}/{record.get('original','')}",
                "status_code": record.get("statuscode"),
                "mime_type": record.get("mimetype"),
            })

        return snapshots

    except Exception as e:
        print(f"[wayback] CDX error for {domain}: {e}")
        return []


def get_first_and_last_seen(snapshots: list) -> dict:
    """
    Given a list of snapshots, find the earliest and most
    recent dates the domain was seen alive.

    Why this matters:
    'First seen' = when the scam site went live
    'Last seen'  = when it was taken down or abandoned

    The gap between these two dates is the scam's operational window.
    Cross-referencing this with victim complaint dates from blockchain
    transactions shows exactly when people were being defrauded.

    Returns dict with first_seen, last_seen, operational_days.
    """
    if not snapshots:
        return {
            "first_seen": None,
            "last_seen": None,
            "operational_days": None,
        }

    dates = []
    for snap in snapshots:
        ts = snap.get("timestamp")
        if ts:
            try:
                dates.append(datetime.strptime(ts, "%Y-%m-%d"))
            except ValueError:
                continue

    if not dates:
        return {
            "first_seen": None,
            "last_seen": None,
            "operational_days": None,
        }

    first = min(dates)
    last = max(dates)
    op_days = (last - first).days + 1

    return {
        "first_seen": first.strftime("%Y-%m-%d"),
        "last_seen": last.strftime("%Y-%m-%d"),
        "operational_days": op_days,
    }


def get_risk_flags(wayback_data: dict) -> list:
    """
    Generates risk flags from Wayback Machine findings.

    Returns list of plain-English flag strings.
    """
    flags = []

    if not wayback_data.get("available"):
        flags.append(
            "No Wayback Machine snapshot — site may never have existed "
            "or was actively blocked from archiving"
        )
        return flags

    op_days = wayback_data.get("operational_days")
    if op_days is not None:
        if op_days < 14:
            flags.append(
                f"Site was only active for {op_days} days — "
                "short operational window typical of hit-and-run scams"
            )
        elif op_days < 60:
            flags.append(
                f"Site was active for only {op_days} days"
            )

    total_snaps = wayback_data.get("total_snapshots", 0)
    if total_snaps == 1:
        flags.append(
            "Only one archive snapshot found — site was crawled once then disappeared"
        )

    return flags


def analyze_domain_wayback(domain: str) -> dict:
    """
    MAIN FUNCTION — call this from app.py and graph_builder.py.

    Combines availability check + full snapshot history +
    operational window + risk flags into one complete dict.

    Returns:
      - domain             : input domain
      - available          : has any snapshot
      - closest_snapshot   : most recent snapshot info
      - all_snapshots      : list of historical snapshots
      - first_seen         : first archive date
      - last_seen          : most recent archive date
      - operational_days   : how long site was active
      - total_snapshots    : number of snapshots found
      - risk_flags         : list of plain-English flags
    """
    print(f"[wayback] Analyzing: {domain}")

    closest = check_availability(domain)
    all_snaps = get_all_snapshots(domain, limit=10)
    timeline = get_first_and_last_seen(all_snaps)
    
    result = {
        "domain": domain,
        "available": closest["available"],
        "closest_snapshot": closest,
        "all_snapshots": all_snaps,
        "first_seen": timeline["first_seen"],
        "last_seen": timeline["last_seen"],
        "operational_days": timeline["operational_days"],
        "total_snapshots": len(all_snaps),
    }

    result["risk_flags"] = get_risk_flags(result)
    return result
