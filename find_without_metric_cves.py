"""
Find CVEs in nvd_cve.db that have NO CVSS metric and NO SSVC metric.

Why these exist: NVD sometimes publishes a CVE with vulnStatus such as
"Awaiting Analysis", "Received", or "Deferred" before any CVSS/SSVC scoring
is attached. That is a data gap, not a loader bug.

Usage:
    python find_cves_without_metrics.py            # print, human-readable
    python find_cves_without_metrics.py --json     # print as JSON
    python find_cves_without_metrics.py --csv      # print as CSV
"""

import argparse
import csv
import json
import os
import sqlite3
import sys

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nvd_cve.db")

SQL = """
SELECT
    c.id                                   AS cve_id,
    c.published                            AS published,
    c.lastModified                         AS last_modified,
    c.vulnStatus                           AS vuln_status,
    (SELECT d.value
       FROM descriptions d
      WHERE d.cve_id = c.id AND d.lang = 'en'
      LIMIT 1)                             AS description_en
FROM cves c
WHERE NOT EXISTS (
        SELECT 1 FROM cvss_metrics m WHERE m.cve_id = c.id
      )
  AND NOT EXISTS (
        SELECT 1 FROM ssvc_metrics m WHERE m.cve_id = c.id
      )
ORDER BY c.published, c.id
"""


def fetch(db_path):
    if not os.path.exists(db_path):
        sys.exit(f"DB not found: {db_path}")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        cur.execute(SQL)
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def print_human(rows):
    if not rows:
        print("No CVEs without metrics. ✅")
        return
    print(f"{len(rows)} CVE(s) without any CVSS or SSVC metric:\n")
    for r in rows:
        desc = (r["description_en"] or "").strip()
        if len(desc) > 120:
            desc = desc[:117] + "..."
        print(f"  {r['cve_id']}")
        print(f"    published : {r['published']}")
        print(f"    modified  : {r['last_modified']}")
        print(f"    status    : {r['vuln_status']}")
        print(f"    desc      : {desc or '(none)'}")
        print()


def print_json(rows):
    print(json.dumps(rows, indent=2, ensure_ascii=False))


def print_csv(rows):
    if not rows:
        return
    writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)


def main():
    ap = argparse.ArgumentParser(
        description="List CVEs in nvd_cve.db with no CVSS and no SSVC metric."
    )
    ap.add_argument("--db", default=DB_PATH, help="Path to nvd_cve.db")
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--json", action="store_true", help="Output JSON")
    grp.add_argument("--csv", action="store_true", help="Output CSV")
    args = ap.parse_args()

    rows = fetch(args.db)

    if args.json:
        print_json(rows)
    elif args.csv:
        print_csv(rows)
    else:
        print_human(rows)


if __name__ == "__main__":
    main()