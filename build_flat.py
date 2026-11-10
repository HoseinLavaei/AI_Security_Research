#!/usr/bin/env python3
"""
Build `cves_flat` — the final flat table (assignment step 4).

One row per (cve_id, product). Columns match the assignment spec exactly:

    cve_id, product, group_name, published, cwe,
    cvss_version, cvss_score, severity, C, I, A,
    epss, epss_date, advisory_url, validation_status

Selection rules:
  cwe          : primary CWE from `weaknesses` (prefer nvd@nist.gov source,
                 then Primary type, then alphabetical)
  cvss_*       : one CVSS row per CVE, chosen by version preference
                 v4.0 > v3.1 > v3.0 > v2, then Primary > Secondary,
                 then NVD source over CNA
  C/I/A        : from that same CVSS row, with COALESCE(v3-name, v4-name)
                 so v3.x AND v4.0 rows both populate
  epss         : joined from epss table
  advisory_url : joined from advisory_url view (DEDUPED to 1 row per pair)
  validation_status :
      confirmed_cpe      — has CPE evidence (strongest)
      confirmed_purl     — has packageURL evidence
      confirmed_affected — has affected.product evidence
      confirmed_advisory — advisory_url on official repo / vendor / patch
      description_match  — only description keyword matched
      unverified         — only source_file evidence

Fixes vs v1:
  * C/I/A: COALESCE with vuln*Impact fields for CVSS v4.0 rows
  * advisory_url join: SELECT DISTINCT prevents row triplication

Idempotent: DROP+CREATE each run.

Usage:
    python build_flat.py               # build + report
    python build_flat.py --report-only # just print stats
"""

import argparse
import os
import sqlite3
import sys

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nvd_cve.db")


def get_columns(cur, table):
    try:
        return [r[1] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()]
    except sqlite3.OperationalError:
        return []


def pick(cols, cands):
    for c in cands:
        if c in cols:
            return c
    return None


def build(conn):
    cur = conn.cursor()

    for t in ("cves", "products", "cve_products", "epss"):
        if not get_columns(cur, t):
            sys.exit(f"missing table: {t}")
    if not get_columns(cur, "advisory_url"):
        sys.exit("advisory_url view missing — run build_cve_products.py first")

    # --- cvss_metrics column detection ----------------------------------
    cm_cols = get_columns(cur, "cvss_metrics")
    print(f"cvss_metrics cols : {len(cm_cols)} columns")

    col_ci = pick(cm_cols, ["confidentialityImpact", "confidentiality_impact"])
    col_ii = pick(cm_cols, ["integrityImpact",       "integrity_impact"])
    col_ai = pick(cm_cols, ["availabilityImpact",    "availability_impact"])

    # CVSS v4.0 uses vuln*Impact instead of *Impact
    col_ci_v4 = pick(cm_cols, ["vulnConfidentialityImpact", "vuln_confidentiality_impact"])
    col_ii_v4 = pick(cm_cols, ["vulnIntegrityImpact",       "vuln_integrity_impact"])
    col_ai_v4 = pick(cm_cols, ["vulnAvailabilityImpact",    "vuln_availability_impact"])

    print(f"  impact cols (v3) : {col_ci} / {col_ii} / {col_ai}")
    print(f"  impact cols (v4) : {col_ci_v4} / {col_ii_v4} / {col_ai_v4}")

    def coalesce_expr(c3, c4):
        parts = [x for x in (c3, c4) if x]
        if not parts:
            return "NULL"
        return "COALESCE(" + ", ".join(parts) + ")"

    expr_ci = coalesce_expr(col_ci, col_ci_v4)
    expr_ii = coalesce_expr(col_ii, col_ii_v4)
    expr_ai = coalesce_expr(col_ai, col_ai_v4)

    # --- weaknesses column detection ------------------------------------
    wk_cols = get_columns(cur, "weaknesses")
    col_wk_val = pick(wk_cols, ["description", "value", "cwe", "cwe_id", "id"])
    col_wk_src = pick(wk_cols, ["source", "provider"])
    col_wk_typ = pick(wk_cols, ["type", "kind"])
    if not col_wk_val:
        sys.exit(f"cannot find CWE value column in weaknesses ({wk_cols})")
    print(f"  weaknesses value : {col_wk_val}")

    src_expr = f"COALESCE({col_wk_src},'')" if col_wk_src else "''"
    typ_expr = f"COALESCE({col_wk_typ},'')" if col_wk_typ else "''"

    # --- CVSS version ranking -------------------------------------------
    kinds = [r[0] for r in cur.execute(
        "SELECT DISTINCT metric_kind FROM cvss_metrics").fetchall()]

    def kind_rank(k):
        kl = str(k).lower()
        if "v4" in kl or "40" in kl:     return 1
        if "v31" in kl or "3.1" in kl:   return 2
        if "v30" in kl or "3.0" in kl:   return 3
        if "v2" in kl:                   return 4
        return 99

    case_parts = [f"WHEN metric_kind = '{k}' THEN {kind_rank(k)}" for k in kinds]
    kind_rank_sql = "CASE " + " ".join(case_parts) + " ELSE 99 END"

    print("building cves_flat ...")
    cur.execute("DROP TABLE IF EXISTS cves_flat")
    cur.execute(f"""
    CREATE TABLE cves_flat AS
    WITH
    cvss_pick AS (
        SELECT cve_id, metric_kind, baseScore, baseSeverity, source, type,
               {expr_ci} AS C,
               {expr_ii} AS I,
               {expr_ai} AS A,
               ROW_NUMBER() OVER (
                   PARTITION BY cve_id
                   ORDER BY {kind_rank_sql},
                            CASE WHEN lower(type)   ='primary'    THEN 0 ELSE 1 END,
                            CASE WHEN lower(source) LIKE '%nist%' THEN 0 ELSE 1 END
               ) AS rn
        FROM cvss_metrics
    ),
    cvss_best AS (SELECT * FROM cvss_pick WHERE rn = 1),
    cwe_ranked AS (
        SELECT cve_id, {col_wk_val} AS cwe_value,
               ROW_NUMBER() OVER (
                   PARTITION BY cve_id
                   ORDER BY CASE WHEN lower({src_expr}) LIKE '%nist%' THEN 0 ELSE 1 END,
                            CASE WHEN lower({typ_expr}) ='primary'    THEN 0 ELSE 1 END,
                            {col_wk_val}
               ) AS rn
        FROM weaknesses
    ),
    cwe_best AS (SELECT cve_id, cwe_value AS cwe FROM cwe_ranked WHERE rn = 1),
    evidence AS (
        SELECT cve_id, product,
               MAX(CASE evidence WHEN 'cpe'         THEN 1 ELSE 0 END) AS has_cpe,
               MAX(CASE evidence WHEN 'purl'        THEN 1 ELSE 0 END) AS has_purl,
               MAX(CASE evidence WHEN 'affected'    THEN 1 ELSE 0 END) AS has_affected,
               MAX(CASE evidence WHEN 'source_file' THEN 1 ELSE 0 END) AS has_source_file,
               MAX(CASE evidence WHEN 'description' THEN 1 ELSE 0 END) AS has_desc
        FROM cve_products
        GROUP BY cve_id, product
    )
    SELECT
        c.id                AS cve_id,
        cp.product          AS product,
        p.group_name        AS group_name,
        c.published         AS published,
        cwe.cwe             AS cwe,
        cv.metric_kind      AS cvss_version,
        cv.baseScore        AS cvss_score,
        cv.baseSeverity     AS severity,
        cv.C                AS C,
        cv.I                AS I,
        cv.A                AS A,
        e.epss              AS epss,
        e.epss_date         AS epss_date,
        au.url              AS advisory_url,
        CASE
            WHEN ev.has_cpe         = 1 THEN 'confirmed_cpe'
            WHEN ev.has_purl        = 1 THEN 'confirmed_purl'
            WHEN ev.has_affected    = 1 THEN 'confirmed_affected'
            WHEN au.source_kind IN
                 ('official_repo','vendor_advisory','ghsa','patch')
                                    THEN 'confirmed_advisory'
            WHEN ev.has_desc        = 1 THEN 'description_match'
            WHEN ev.has_source_file = 1 THEN 'unverified'
            ELSE 'unverified'
        END                 AS validation_status
    FROM cves c
    JOIN (SELECT DISTINCT cve_id, product FROM cve_products) cp
                                     ON cp.cve_id = c.id
    JOIN products p                  ON p.product  = cp.product
    LEFT JOIN cvss_best    cv        ON cv.cve_id  = c.id
    LEFT JOIN cwe_best     cwe       ON cwe.cve_id = c.id
    LEFT JOIN epss         e         ON e.cve_id   = c.id
    LEFT JOIN (
        SELECT DISTINCT cve_id, product, url, source_kind FROM advisory_url
    ) au                              ON au.cve_id  = c.id AND au.product = cp.product
    LEFT JOIN evidence     ev        ON ev.cve_id  = c.id AND ev.product = cp.product
    ;
    """)
    conn.commit()

    for idx, col in [
        ("idx_flat_cve",  "cve_id"),
        ("idx_flat_prod", "product"),
        ("idx_flat_grp",  "group_name"),
        ("idx_flat_epss", "epss"),
    ]:
        cur.execute(f"CREATE INDEX IF NOT EXISTS {idx} ON cves_flat({col})")
    conn.commit()

    n = cur.execute("SELECT COUNT(*) FROM cves_flat").fetchone()[0]
    print(f"  -> cves_flat has {n} rows")


def report(conn):
    cur = conn.cursor()
    print("\n=== cves_flat report ===")
    print("rows             :", cur.execute("SELECT COUNT(*) FROM cves_flat").fetchone()[0])
    print("distinct CVEs    :", cur.execute("SELECT COUNT(DISTINCT cve_id) FROM cves_flat").fetchone()[0])
    print("distinct products:", cur.execute("SELECT COUNT(DISTINCT product) FROM cves_flat").fetchone()[0])

    print("\nnull / empty profile per column:")
    cols = [r[1] for r in cur.execute("PRAGMA table_info(cves_flat)")]
    for col in cols:
        n = cur.execute(
            f"SELECT COUNT(*) FROM cves_flat WHERE {col} IS NULL OR {col}=''"
        ).fetchone()[0]
        flag = " !!" if (n > 0 and col in (
            "cve_id", "product", "group_name", "published",
            "cvss_score", "severity", "epss", "epss_date", "advisory_url"
        )) else ""
        print(f"  {col:<22}{n}{flag}")

    print("\nvalidation_status:")
    for st, n in cur.execute("""
        SELECT validation_status, COUNT(*) FROM cves_flat
        GROUP BY validation_status ORDER BY 2 DESC
    """):
        print(f"  {st:<22}{n}")

    print("\nseverity:")
    for st, n in cur.execute("""
        SELECT COALESCE(severity,'(null)'), COUNT(*) FROM cves_flat
        GROUP BY severity ORDER BY 2 DESC
    """):
        print(f"  {st:<22}{n}")

    print("\ncvss_version:")
    for st, n in cur.execute("""
        SELECT COALESCE(cvss_version,'(null)'), COUNT(*) FROM cves_flat
        GROUP BY cvss_version ORDER BY 2 DESC
    """):
        print(f"  {st:<22}{n}")

    print("\nC/I/A values (top 10):")
    for row in cur.execute("""
        SELECT C, I, A, COUNT(*) FROM cves_flat
        GROUP BY C, I, A ORDER BY 4 DESC LIMIT 10
    """):
        print(f"  C={row[0]!s:<10} I={row[1]!s:<10} A={row[2]!s:<10} -> {row[3]}")

    print("\nrows per product (top 25):")
    for p, n in cur.execute("""
        SELECT product, COUNT(*) FROM cves_flat
        GROUP BY product ORDER BY 2 DESC LIMIT 25
    """):
        print(f"  {p:<22}{n}")

    print("\nsample rows (3 highest EPSS):")
    for row in cur.execute("""
        SELECT cve_id, product, group_name, cvss_score, severity,
               epss, validation_status, cwe
        FROM cves_flat
        ORDER BY epss DESC LIMIT 3
    """):
        print(f"  {row}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--report-only", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        sys.exit(f"DB not found: {args.db}")

    conn = sqlite3.connect(args.db)
    try:
        if not args.report_only:
            build(conn)
        report(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()