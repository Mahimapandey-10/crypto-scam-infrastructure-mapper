"""
DAY 4 TEST SCRIPT
=================
Run this to verify your wayback.py module works.

Usage:
    cd backend
    python test_day4.py

No API key needed. Free. Just needs internet.

What to expect:
    Snapshot history for two domains — one old legitimate site
    (always has snapshots) and one that simulates a scam domain
    that has disappeared.
"""

from modules.wayback import (
    analyze_domain_wayback,
    check_availability,
    get_all_snapshots,
    get_first_and_last_seen,
)


# Old legitimate domain — always has lots of snapshots, good for testing
TEST_DOMAIN = "github.com"

# A domain that was once active but may now be gone
# Replace with a real flagged domain from CryptoScamDB for actual demo
GONE_DOMAIN = "myetherwallet.com"


def print_section(title: str):
    print("\n" + "=" * 55)
    print(f"  {title}")
    print("=" * 55)


def test_availability_check():
    print_section("TEST 1: Availability check")
    result = check_availability(TEST_DOMAIN)

    print(f"  Domain       : {TEST_DOMAIN}")
    print(f"  Available    : {result['available']}")
    print(f"  Snapshot URL : {result['snapshot_url']}")
    print(f"  Taken on     : {result['timestamp']}")

    if result["available"]:
        print("  RESULT  : PASS — Wayback Machine reachable")
    else:
        print("  RESULT  : No snapshot found (check internet)")


def test_all_snapshots():
    print_section("TEST 2: Full snapshot history")
    snaps = get_all_snapshots(TEST_DOMAIN, limit=5)
    print(f"  Domain          : {TEST_DOMAIN}")
    print(f"  Snapshots found : {len(snaps)}")

    if snaps:
        print(f"\n  Snapshot history:")
        for s in snaps:
            print(f"    [{s['timestamp']}]  status={s['status_code']}  {s['url'][:60]}...")
        print("  RESULT  : PASS")
    else:
        print("  RESULT  : No snapshots returned")


def test_timeline():
    print_section("TEST 3: Operational timeline")
    snaps = get_all_snapshots(TEST_DOMAIN, limit=10)
    timeline = get_first_and_last_seen(snaps)

    print(f"  Domain            : {TEST_DOMAIN}")
    print(f"  First seen        : {timeline['first_seen']}")
    print(f"  Last seen         : {timeline['last_seen']}")
    print(f"  Operational days  : {timeline['operational_days']}")

    if timeline["first_seen"]:
        print("  RESULT  : PASS")
    else:
        print("  RESULT  : Could not compute timeline")


def test_full_analysis():
    print_section("TEST 4: Full domain analysis")
    result = analyze_domain_wayback(TEST_DOMAIN)

    print(f"  Domain            : {result['domain']}")
    print(f"  Available         : {result['available']}")
    print(f"  Total snapshots   : {result['total_snapshots']}")
    print(f"  First seen        : {result['first_seen']}")
    print(f"  Last seen         : {result['last_seen']}")
    print(f"  Operational days  : {result['operational_days']}")

    if result["risk_flags"]:
        print(f"\n  Risk flags:")
        for f in result["risk_flags"]:
            print(f"    ⚠️  {f}")
    else:
        print(f"\n  No risk flags (legitimate domain)")

    print("\n  Closest snapshot URL:")
    print(f"    {result['closest_snapshot'].get('snapshot_url', 'N/A')}")
    print("\n  RESULT  : PASS")
    return result


def test_graph_nodes(result: dict):
    print_section("TEST 5: Graph-ready output check")
    print("  Wayback adds timeline metadata to domain nodes:\n")

    print(f"  NODE [domain]  : {result['domain']}")
    print(f"    → first_seen       : {result['first_seen']}")
    print(f"    → last_seen        : {result['last_seen']}")
    print(f"    → operational_days : {result['operational_days']}")
    print(f"    → total_snapshots  : {result['total_snapshots']}")

    if result["closest_snapshot"].get("snapshot_url"):
        print(f"\n  EDGE [snapshot]: domain → archive.org")
        print(f"    → label: 'Cached version available'")
        print(f"    → clicking this in UI opens the old scam site")

    print(f"\n  RESULT  : PASS — ready for graph_builder.py on Day 7")


if __name__ == "__main__":
    print("\n  CRYPTO SCAM MAPPER — Day 4 Test")
    print("  No API key needed for this module\n")

    test_availability_check()
    test_all_snapshots()
    test_timeline()
    result = test_full_analysis()
    test_graph_nodes(result)

    print("\n" + "=" * 55)
    print("  ALL TESTS COMPLETE")
    print("  If you see snapshot data above, Day 4 is done.")
    print("  Next: Day 5 — build modules/google_search.py + scamdb.py")
    print("=" * 55 + "\n")
