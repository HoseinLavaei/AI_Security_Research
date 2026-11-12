#!/usr/bin/env python3
"""
Fetch EPSS scores from FIRST.org for every CVE in the DB.

API:  https://api.first.org/data/v1/epss?cve=CVE-...,CVE-...,...
      - up to 100 CVEs per request (we use 100)
      - returns latest scores by default
      - response fields: cve, epss (str), percentile (str), date (YYYY-MM-DD)

Writes to `epss` table:
    cve_id      TEXT PRIMARY KEY
    epss        REAL      -- 0.0 .. 1.0
    percentile  REAL      -- 0.0 .. 1.0
    epss_date   TEXT      -- YYYY-MM-DD  (this is the assignment's `epss_date`)
    fetched_at  TEXT      -- ISO timestamp of our fetch

Idempotent: INSERT OR REPLACE per row.

Usage:
    python fetch_epss.py             # fetch missing CVEs only (incremental)
    python fetch_epss.py --refresh   # refetch ALL CVEs (update existing)
    python fetch_epss.py --dry-run   # show plan, no network
    python fetch_epss.py --report    # just print current epss table state
"""

import argparse
import datetime
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nvd_cve.db")
EPSS_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100
SLEEP_BETWEEN = 0.5     # seconds
RETRIES = 3
RETRY_BACKOFF = 2.0     # seconds, multiplied by attempt number


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

CREATE_SQL = """
CREATE TABLE IF NOT EXISTS epss (
    cve_id     TEXT PRIMARY KEY,
    epss       REAL,
    percentile REAL,
    epss_date  TEXT,
    fetched_at TEXT
);
"""


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def http_get_json(url, timeout=30):
    req = urllib.request.Request(url, headers={
        "User-Agent": "nvd-cve-epss-fetcher/1.0",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    return json.loads(body)


def fetch_batch(cve_ids):
    """
    Query EPSS for a list of CVE IDs.
    Returns list of dicts: [{cve, epss, percentile, date}, ...]
    Raises on unrecoverable errors.
    """
    url = EPSS_URL + "?cve=" + ",".join(cve_ids)
    last_err = None
    for attempt in range(1, RETRIES + 1):
        try:
            data = http_get_json(url)
            if data.get("status") != "OK":
                raise RuntimeError(f"API status={data.get('status')} body={data}")
            return data.get("data", [])
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code in (429, 500, 502, 503, 504):
                wait = RETRY_BACKOFF * attempt
                print(f"    HTTP {e.code} — retrying in {wait:.1f}s "
                      f"(attempt {attempt}/{RETRIES})")
                time.sleep(wait)
                continue
            raise
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            last_err = e
            wait = RETRY_BACKOFF * attempt
            print(f"    network/parse error ({e}) — retrying in {wait:.1f}s "
                  f"(attempt {attempt}/{RETRIES})")
            time.sleep(wait)
    raise RuntimeError(f"giving up after {RETRIES} retries: {last_err}")


# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------

def ensure_table(conn):
    conn.execute(CREATE_SQL)
    conn.commit()


def get_all_cves(conn):
    cur = conn.cursor()
    return [r[0] for r in cur.execute("SELECT id FROM cves ORDER BY id")]


def get_existing(conn):
    cur = conn.cursor()
    try:
        return {r[0] for r in cur.execute("SELECT cve_id FROM epss")}
    except sqlite3.OperationalError:
        return set()


def upsert_batch(conn, rows, fetched_at):
    cur = conn.cursor()
    n = 0
    for r in rows:
        cve = r.get("cve")
        if not cve:
            continue
        try:
            epss_val = float(r["epss"])
        except (KeyError, ValueError, TypeError):
            epss_val = None
        try:
            pct_val = float(r["percentile"])
        except (KeyError, ValueError, TypeError):
            pct_val = None
        date_val = r.get("date")
        cur.execute("""
            INSERT OR REPLACE INTO epss
                (cve_id, epss, percentile, epss_date, fetched_at)
            VALUES (?, ?, ?, ?, ?)
        """, (cve, epss_val, pct_val, date_val, fetched_at))
        n += 1
    conn.commit()
    return n


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def report(conn):
    cur = conn.cursor()
    print("\n=== epss table ===")

    try:
        n_total, n_scored, n_missing = cur.execute("""
            SELECT
                (SELECT COUNT(*) FROM cves) AS total,
                (SELECT COUNT(*) FROM epss) AS scored,
                (SELECT COUNT(*) FROM cves c
                  WHERE c.id NOT IN (SELECT cve_id FROM epss)) AS missing
        """).fetchone()
    except sqlite3.OperationalError:
        print("  (epss table does not exist yet)")
        return

    print(f"  CVEs in DB        : {n_total}")
    print(f"  EPSS scored       : {n_scored}")
    print(f"  Missing EPSS      : {n_missing}")

    if n_scored:
        row = cur.execute("""
            SELECT
                MIN(epss), MAX(epss), AVG(epss),
                MIN(epss_date), MAX(epss_date)
            FROM epss
        """).fetchone()
        print(f"  epss range        : {row[0]:.4f} .. {row[1]:.4f} (mean {row[2]:.4f})")
        print(f"  epss_date range   : {row[3]} .. {row[4]}")

        print("\n  top 10 by epss:")
        for cve, e, p in cur.execute("""
            SELECT cve_id, epss, percentile FROM epss
            ORDER BY epss DESC LIMIT 10
        """):
            print(f"    {cve:<18}epss={e:.4f}  percentile={p:.4f}")

        print("\n  epss distribution (buckets):")
        for lo, hi in [(0.0, 0.01), (0.01, 0.1), (0.1, 0.5),
                       (0.5, 0.9), (0.9, 1.0)]:
            n = cur.execute(
                "SELECT COUNT(*) FROM epss WHERE epss >= ? AND epss < ?",
                (lo, hi)
            ).fetchone()[0]
            print(f"    [{lo:.2f}, {hi:.2f}) : {n}")

    if n_missing:
        print("\n  CVEs with no EPSS score (first 20):")
        for (cid,) in cur.execute("""
            SELECT c.id FROM cves c
            WHERE c.id NOT IN (SELECT cve_id FROM epss)
            ORDER BY c.id LIMIT 20
        """):
            print(f"    {cid}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--refresh", action="store_true",
                    help="Refetch ALL CVEs (default: only missing)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Show plan, don't call the API")
    ap.add_argument("--report", action="store_true",
                    help="Just print the current epss table and exit")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        sys.exit(f"DB not found: {args.db}")

    conn = sqlite3.connect(args.db)
    try:
        ensure_table(conn)

        if args.report:
            report(conn)
            return

        all_cves = get_all_cves(conn)
        existing = get_existing(conn)

        if args.refresh:
            todo = all_cves
            print(f"refresh mode: fetching all {len(todo)} CVEs")
        else:
            todo = [c for c in all_cves if c not in existing]
            print(f"incremental mode: {len(todo)} missing of {len(all_cves)} total")

        if not todo:
            print("nothing to do — every CVE already has an EPSS score")
            report(conn)
            return

        if args.dry_run:
            batches = (len(todo) + BATCH_SIZE - 1) // BATCH_SIZE
            print(f"would fetch {batches} batches of ≤{BATCH_SIZE}")
            for i in range(0, min(200, len(todo)), BATCH_SIZE):
                print(f"  batch {i//BATCH_SIZE + 1}: "
                      f"{todo[i:i+BATCH_SIZE][:3]}... "
                      f"({len(todo[i:i+BATCH_SIZE])} IDs)")
            return

        fetched_at = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
        total_stored = 0
        total_returned = 0

        for i in range(0, len(todo), BATCH_SIZE):
            batch = todo[i:i+BATCH_SIZE]
            bnum = i // BATCH_SIZE + 1
            btot = (len(todo) + BATCH_SIZE - 1) // BATCH_SIZE
            print(f"  batch {bnum}/{btot}: {len(batch)} IDs ...", end="", flush=True)
            try:
                rows = fetch_batch(batch)
            except Exception as e:
                print(f" FAILED ({e})")
                continue
            n = upsert_batch(conn, rows, fetched_at)
            total_returned += len(rows)
            total_stored += n
            short = len(batch) - len(rows)
            note = f"  ({short} not in EPSS dataset)" if short else ""
            print(f" ok, stored {n}{note}")
            time.sleep(SLEEP_BETWEEN)

        print(f"\nDone. Returned {total_returned} rows, stored {total_stored}.")
        report(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()