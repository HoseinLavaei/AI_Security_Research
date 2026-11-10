#!/usr/bin/env python3
"""
Build `cve_products` (CVE↔product M:N) and `advisory_url` (VIEW) — v2.

Fixes vs v1:
  * CPE matching done Python-side with normalized comparison
    (so `open_webui` in criteria matches normalized `openwebui` in products)
  * affected.product matching done Python-side, normalized
  * source_file evidence uses the real schema (file_id / filename)
  * description-fallback evidence for CVEs still unmapped after 1-4
    (uses each product's canonical name + cpe_products as keywords,
     min length 4, substring against the English description)

Evidence precedence (a CVE can carry multiple evidence rows per product):
    cpe          — normalized CPE product matched
    purl         — packageURL substring matched
    affected     — affected.product (normalized) matched
    source_file  — CVE came in via that tool's NVD keyword file
    description  — English description contains the product name (last resort)

advisory_url view keeps: official_repo > ghsa > vendor advisory > patch
> release notes > other reference > NVD detail page.

Usage:
    python build_cve_products.py               # rebuild + report
    python build_cve_products.py --report-only # just print report
    python build_cve_products.py --diag        # extra URL diagnostics
"""

import argparse
import json
import os
import re
import sqlite3
import sys

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nvd_cve.db")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def norm(s):
    if not s:
        return ""
    return re.sub(r"[^a-z0-9]", "", s.lower())


def extract_cpe_pair(criteria):
    """cpe:2.3:a:vendor:product:... -> (vendor_norm, product_norm)."""
    if not criteria:
        return None, None
    parts = criteria.split(":")
    if len(parts) < 5:
        return None, None
    return norm(parts[3]), norm(parts[4])


def get_columns(cur, table):
    try:
        return [r[1] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()]
    except sqlite3.OperationalError:
        return []


# ---------------------------------------------------------------------------
# Load product lookup into Python
# ---------------------------------------------------------------------------

def load_products(cur):
    rows = cur.execute("""
        SELECT product, product_norm, official_repo,
               cpe_vendors, cpe_products, purl_substrings,
               aliases_norm, source_file, tier
        FROM products
    """).fetchall()
    out = {}
    for (product, pnorm, repo, cv_j, cp_j, purl_j, ali_j, src, tier) in rows:
        out[product] = {
            "product_norm":   pnorm,
            "official_repo":  repo,
            "cpe_vendors":    set(json.loads(cv_j   or "[]")),
            "cpe_products":   set(json.loads(cp_j   or "[]")),
            "purl_substrings":json.loads(purl_j     or "[]"),
            "aliases":        set(json.loads(ali_j  or "[]")),
            "source_file":    src,
            "tier":           tier,
        }
    return out


# ---------------------------------------------------------------------------
# cve_products
# ---------------------------------------------------------------------------

def build_cve_products(conn):
    cur = conn.cursor()
    print("building cve_products ...")

    products = load_products(cur)
    print(f"  loaded {len(products)} products")

    cur.execute("DROP TABLE IF EXISTS cve_products")
    cur.execute("""
        CREATE TABLE cve_products (
            cve_id          TEXT NOT NULL,
            product         TEXT NOT NULL,
            evidence        TEXT NOT NULL,
            evidence_detail TEXT,
            PRIMARY KEY (cve_id, product, evidence)
        )
    """)
    cur.execute("CREATE INDEX idx_cve_products_cve  ON cve_products(cve_id)")
    cur.execute("CREATE INDEX idx_cve_products_prod ON cve_products(product)")

    counts = {}

    # ---- 1. CPE evidence — Python-side normalized match ------------------
    cpe_rows = cur.execute("""
        SELECT DISTINCT n.cve_id, m.criteria
        FROM configuration_nodes n
        JOIN cpe_matches m ON m.node_row_id = n.rowid
    """).fetchall()
    cpe_hits = 0
    for cve_id, criteria in cpe_rows:
        v, p = extract_cpe_pair(criteria)
        if not p:
            continue
        for product, info in products.items():
            if p in info["cpe_products"]:
                detail = f"{v}:{p}" if v in info["cpe_vendors"] else f"{v}:{p} (vendor≠list)"
                cur.execute("""
                    INSERT OR IGNORE INTO cve_products
                        (cve_id, product, evidence, evidence_detail)
                    VALUES (?, ?, 'cpe', ?)
                """, (cve_id, product, detail))
                if cur.rowcount:
                    cpe_hits += 1
    counts["cpe"] = cpe_hits
    print(f"  cpe        : {cpe_hits}")

    # ---- 2. purl evidence ------------------------------------------------
    purl_hits = 0
    for product, info in products.items():
        for sub in info["purl_substrings"]:
            cur.execute("""
                INSERT OR IGNORE INTO cve_products
                    (cve_id, product, evidence, evidence_detail)
                SELECT DISTINCT a.cve_id, ?, 'purl', a.packageURL
                FROM affected a
                WHERE a.packageURL IS NOT NULL
                  AND lower(a.packageURL) LIKE ?
            """, (product, f"%{sub.lower()}%"))
            purl_hits += cur.rowcount
    counts["purl"] = purl_hits
    print(f"  purl       : {purl_hits}")

    # ---- 3. affected.product — Python-side normalized match --------------
    aff_rows = cur.execute("""
        SELECT DISTINCT cve_id, vendor, product FROM affected
    """).fetchall()
    aff_hits = 0
    for cve_id, vendor, prod_val in aff_rows:
        if not prod_val:
            continue
        # the affected.product column already holds the bare product
        cands = {norm(prod_val)}
        # also try the last slash-segment (for the rare "vendor/prod" full form)
        cands.add(norm(prod_val.split("/")[-1]))
        for product, info in products.items():
            keys = info["cpe_products"] | info["aliases"] | {info["product_norm"]}
            if cands & keys:
                cur.execute("""
                    INSERT OR IGNORE INTO cve_products
                        (cve_id, product, evidence, evidence_detail)
                    VALUES (?, ?, 'affected', ?)
                """, (cve_id, product, f"{vendor}/{prod_val}"))
                if cur.rowcount:
                    aff_hits += 1
    counts["affected"] = aff_hits
    print(f"  affected   : {aff_hits}")

    # ---- 4. source_file evidence — correct schema -----------------------
    csf_cols = get_columns(cur, "cve_source_files")
    sf_cols  = get_columns(cur, "source_files")
    if "file_id" in csf_cols and "file_id" in sf_cols and "filename" in sf_cols:
        src_hits = 0
        for product, info in products.items():
            src_file = info["source_file"]
            if not src_file:
                continue
            cur.execute("""
                INSERT OR IGNORE INTO cve_products
                    (cve_id, product, evidence, evidence_detail)
                SELECT DISTINCT csf.cve_id, ?, 'source_file', ?
                FROM cve_source_files csf
                JOIN source_files sf ON sf.file_id = csf.file_id
                WHERE sf.filename = ?
            """, (product, src_file, src_file))
            src_hits += cur.rowcount
        counts["source_file"] = src_hits
        print(f"  source_file: {src_hits}")
    else:
        print(f"  source_file: SKIPPED (schema {csf_cols} / {sf_cols})")
        counts["source_file"] = 0

    # ---- 5. description fallback — only for still-unmapped CVEs ---------
    unmapped = [r[0] for r in cur.execute("""
        SELECT id FROM cves
        WHERE id NOT IN (SELECT DISTINCT cve_id FROM cve_products)
    """).fetchall()]
    desc_hits = 0
    if unmapped:
        ph = ",".join("?" * len(unmapped))
        descs = {cid: (v or "").lower() for cid, v in cur.execute(f"""
            SELECT d.cve_id, d.value
            FROM descriptions d
            WHERE d.lang='en' AND d.cve_id IN ({ph})
        """, unmapped).fetchall()}
        for cve_id in unmapped:
            text = descs.get(cve_id, "")
            if not text:
                continue
            for product, info in products.items():
                # keywords: canonical name + cpe_products, min length 4
                kws = [info["product_norm"]] + list(info["cpe_products"])
                matched_kw = None
                for kw in kws:
                    if len(kw) >= 4 and kw in text:
                        matched_kw = kw
                        break
                if matched_kw:
                    cur.execute("""
                        INSERT OR IGNORE INTO cve_products
                            (cve_id, product, evidence, evidence_detail)
                        VALUES (?, ?, 'description', ?)
                    """, (cve_id, product, matched_kw))
                    if cur.rowcount:
                        desc_hits += 1
                    break   # one product per CVE via description is enough
        counts["description"] = desc_hits
        print(f"  description: {desc_hits}")
    else:
        counts["description"] = 0

    conn.commit()
    total = cur.execute("SELECT COUNT(*) FROM cve_products").fetchone()[0]
    print(f"  -> TOTAL {total} cve_products rows")


# ---------------------------------------------------------------------------
# advisory_url VIEW
# ---------------------------------------------------------------------------

def build_advisory_view(conn):
    cur = conn.cursor()
    print("building advisory_url view ...")

    ref_cols = get_columns(cur, "cve_references")
    if "url" not in ref_cols:
        print("  ! cve_references.url column missing")
        return
    tags_expr = "lower(COALESCE(r.tags,''))" if "tags" in ref_cols else "''"

    cur.execute("DROP VIEW IF EXISTS advisory_url")
    cur.execute(f"""
    CREATE VIEW advisory_url AS
    WITH ranked AS (
        SELECT
            cp.cve_id,
            cp.product,
            r.url,
            CASE
                WHEN p.official_repo IS NOT NULL
                 AND r.url LIKE p.official_repo || '%'         THEN 1
                WHEN r.url LIKE '%github.com/advisories/GHSA-%' THEN 2
                WHEN {tags_expr} LIKE '%vendor advisory%'       THEN 3
                WHEN {tags_expr} LIKE '%patch%'                 THEN 4
                WHEN {tags_expr} LIKE '%release notes%'         THEN 5
                ELSE 99
            END AS rank
        FROM cve_products cp
        JOIN products p ON p.product = cp.product
        LEFT JOIN cve_references r ON r.cve_id = cp.cve_id
        WHERE r.url IS NOT NULL
    ),
    best AS (
        SELECT cve_id, product, url, rank,
               ROW_NUMBER() OVER (
                   PARTITION BY cve_id, product ORDER BY rank
               ) AS rn
        FROM ranked
    )
    SELECT
        cp.cve_id,
        cp.product,
        COALESCE(b.url, 'https://nvd.nist.gov/vuln/detail/' || cp.cve_id) AS url,
        CASE
            WHEN b.url IS NULL THEN 'nvd_fallback'
            WHEN b.rank = 1    THEN 'official_repo'
            WHEN b.rank = 2    THEN 'ghsa'
            WHEN b.rank = 3    THEN 'vendor_advisory'
            WHEN b.rank = 4    THEN 'patch'
            WHEN b.rank = 5    THEN 'release_notes'
            ELSE 'other_reference'
        END AS source_kind
    FROM cve_products cp
    LEFT JOIN best b
        ON b.cve_id = cp.cve_id
       AND b.product = cp.product
       AND b.rn = 1
    """)
    conn.commit()
    n = cur.execute("SELECT COUNT(*) FROM advisory_url").fetchone()[0]
    print(f"  -> {n} advisory_url rows")


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def report(conn, diag=False):
    cur = conn.cursor()
    print("\n=== summary ===")

    print("cve_products by evidence:")
    for ev, n in cur.execute("""
        SELECT evidence, COUNT(*) FROM cve_products GROUP BY evidence ORDER BY 2 DESC
    """):
        print(f"  {ev:<14}{n}")

    print("\ncve_products per product (all tiers), with source-file baseline:")
    for row in cur.execute("""
        SELECT p.tier, p.product,
               (SELECT COUNT(DISTINCT cve_id) FROM cve_products cp WHERE cp.product=p.product) AS matched,
               (SELECT COUNT(*) FROM cve_source_files csf
                  JOIN source_files sf ON sf.file_id=csf.file_id
                  WHERE p.source_file IS NOT NULL AND sf.filename=p.source_file) AS in_file
        FROM products p
        ORDER BY p.tier, matched DESC
    """):
        tier, prod, matched, in_file = row
        print(f"  T{tier}  {prod:<22} matched={matched:<5} source_file={in_file}")

    print("\nadvisory_url by source_kind:")
    for k, n in cur.execute("""
        SELECT source_kind, COUNT(*) FROM advisory_url GROUP BY source_kind ORDER BY 2 DESC
    """):
        print(f"  {k:<16}{n}")

    n_no_map = cur.execute("""
        SELECT COUNT(*) FROM cves
        WHERE id NOT IN (SELECT DISTINCT cve_id FROM cve_products)
    """).fetchone()[0]
    print(f"\nCVEs with NO product mapping : {n_no_map}")
    if n_no_map and n_no_map <= 40:
        for (cid,) in cur.execute("""
            SELECT id FROM cves
            WHERE id NOT IN (SELECT DISTINCT cve_id FROM cve_products)
            ORDER BY id
        """):
            print(f"    {cid}")
    elif n_no_map:
        print("  first 20:")
        for (cid,) in cur.execute("""
            SELECT id FROM cves
            WHERE id NOT IN (SELECT DISTINCT cve_id FROM cve_products)
            ORDER BY id LIMIT 20
        """):
            print(f"    {cid}")

    if diag:
        print("\n=== diagnostics ===")
        n_ghsa = cur.execute(
            "SELECT COUNT(*) FROM cve_references WHERE url LIKE '%github.com/advisories/GHSA-%'"
        ).fetchone()[0]
        print(f"GHSA URLs in corpus       : {n_ghsa}")
        print("top 10 URL hosts:")
        for row in cur.execute("""
            SELECT
                CASE
                    WHEN url LIKE 'https://github.com/%'   THEN 'github.com'
                    WHEN url LIKE 'https://nvd.nist.gov/%' THEN 'nvd.nist.gov'
                    WHEN url LIKE 'https://%' THEN substr(url, 9, instr(substr(url, 9), '/') - 1)
                    ELSE substr(url, 1, 30)
                END AS host,
                COUNT(*)
            FROM cve_references
            GROUP BY host ORDER BY 2 DESC LIMIT 10
        """):
            print(f"  {row[0]:<24}{row[1]}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--diag", action="store_true", help="Extra URL diagnostics")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        sys.exit(f"DB not found: {args.db}")

    conn = sqlite3.connect(args.db)
    try:
        cur = conn.cursor()
        if not get_columns(cur, "products"):
            sys.exit("products table missing — run build_products.py first")

        if not args.report_only:
            build_cve_products(conn)
            build_advisory_view(conn)

        report(conn, diag=args.diag)
    finally:
        conn.close()


if __name__ == "__main__":
    main()