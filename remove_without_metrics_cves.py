#!/usr/bin/env python3
"""
Remove CVEs that have no CVSS metric and no SSVC metric from nvd_cve.db.

Deletes the CVE and every row that references it in the child tables
(cascade order: cpe_matches -> configuration_nodes, affected_versions ->
affected, then the rest, then cves itself).

Extensible: add more cleanup functions and register them in CLEANUPS.
"""

import argparse
import os
import sqlite3
import sys

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nvd_cve.db")

# Tables that hang off cves directly, with the column referencing cves.id.
CVE_CHILD_TABLES = [
    "descriptions",
    "cveTags",
    "affected",
    "cvss_metrics",
    "ssvc_metrics",
    "weaknesses",
    "cve_references",
    "configuration_nodes",
    "cve_source_files",
]


def find_targets(conn, rule):
    cur = conn.cursor()
    if rule == "no_metrics":
        cur.execute("""
            SELECT c.id FROM cves c
            WHERE NOT EXISTS (SELECT 1 FROM cvss_metrics m WHERE m.cve_id = c.id)
              AND NOT EXISTS (SELECT 1 FROM ssvc_metrics m WHERE m.cve_id = c.id)
        """)
    else:
        raise SystemExit(f"Unknown rule: {rule}")
    return [r[0] for r in cur.fetchall()]


def delete_cves(conn, cve_ids):
    if not cve_ids:
        return {}

    cur = conn.cursor()
    ph = ",".join("?" * len(cve_ids))
    counts = {}

    # Grandchildren first.
    cur.execute(f"""
        DELETE FROM cpe_matches
        WHERE node_row_id IN (
            SELECT rowid FROM configuration_nodes WHERE cve_id IN ({ph})
        )
    """, cve_ids)
    counts["cpe_matches"] = cur.rowcount

    cur.execute(f"""
        DELETE FROM affected_versions
        WHERE affected_row_id IN (
            SELECT rowid FROM affected WHERE cve_id IN ({ph})
        )
    """, cve_ids)
    counts["affected_versions"] = cur.rowcount

    # Direct children.
    for t in CVE_CHILD_TABLES:
        cur.execute(f"DELETE FROM {t} WHERE cve_id IN ({ph})", cve_ids)
        counts[t] = cur.rowcount

    # Parent.
    cur.execute(f"DELETE FROM cves WHERE id IN ({ph})", cve_ids)
    counts["cves"] = cur.rowcount

    return counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--rule", default="no_metrics",
                    choices=["no_metrics"])
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        sys.exit(f"DB not found: {args.db}")

    conn = sqlite3.connect(args.db)
    try:
        ids = find_targets(conn, args.rule)
        print(f"Matched {len(ids)} CVE(s): {', '.join(ids) if ids else '(none)'}")

        if args.dry_run or not ids:
            return

        counts = delete_cves(conn, ids)
        conn.commit()

        print("\nDeleted rows per table:")
        for t, n in counts.items():
            print(f"  {t:<24}{n}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()