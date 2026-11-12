"""
Audit which products are present in nvd_cve.db.
Read-only; does not modify the DB.
"""
import argparse, os, sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nvd_cve.db")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB_PATH)
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    cur = conn.cursor()

    print("=== Distinct CPEs (cpe_matches.criteria) ===")
    for crit, n in cur.execute("""
        SELECT m.criteria, COUNT(DISTINCT n.cve_id) AS n
        FROM cpe_matches m
        JOIN configuration_nodes n ON n.rowid = m.node_row_id
        GROUP BY m.criteria
        ORDER BY n DESC, m.criteria
    """):
        print(f"  {n:>4}  {crit}")

    print("\n=== CVEs with NO CPE at all (affected vendor/product) ===")
    rows = cur.execute("""
        SELECT c.id,
               COALESCE(a.vendor,     '(n/a)') AS vendor,
               COALESCE(a.product,    '(n/a)') AS product,
               COALESCE(a.packageURL, '(n/a)') AS packageURL
        FROM cves c
        LEFT JOIN affected a ON a.cve_id = c.id
        WHERE c.id NOT IN (
            SELECT DISTINCT n.cve_id
            FROM configuration_nodes n
            JOIN cpe_matches m ON m.node_row_id = n.rowid
        )
        ORDER BY c.id
    """).fetchall()
    print(f"  ({len(rows)} CVE×affected row(s))")
    for cve, v, p, pu in rows:
        print(f"  {cve}  {v} / {p}  [{pu}]")

    print("\n=== CVEs with NO CPE and no packageURL — first 120 chars of desc ===")
    rows = cur.execute("""
        SELECT c.id,
               (SELECT d.value FROM descriptions d
                 WHERE d.cve_id = c.id AND d.lang = 'en' LIMIT 1)
        FROM cves c
        WHERE c.id NOT IN (
            SELECT DISTINCT n.cve_id
            FROM configuration_nodes n
            JOIN cpe_matches m ON m.node_row_id = n.rowid
        )
        AND NOT EXISTS (
            SELECT 1 FROM affected a
             WHERE a.cve_id = c.id AND a.packageURL IS NOT NULL
        )
        ORDER BY c.id
    """).fetchall()
    print(f"  ({len(rows)} CVE(s))")
    for cve, desc in rows:
        d = (desc or "").replace("\n", " ")[:120]
        print(f"  {cve}: {d}")

    conn.close()


if __name__ == "__main__":
    main()