"""
Load any number of NVD CVE API 2.0 JSON files into a normalized SQLite DB.

Tables (per entity, not per file):
    source_files, cves, cve_source_files,
    descriptions, cveTags,
    affected, affected_versions,
    cvss_metrics, ssvc_metrics,
    weaknesses, cve_references,
    configuration_nodes, cpe_matches
"""

import glob
import json
import os
import sqlite3

DB_PATH = "nvd_cve.db"
DIR = os.path.dirname(os.path.abspath(__file__))


def q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def sqltype(pytypes) -> str:
    t = {x for x in pytypes if x is not type(None)}
    if not t:
        return "TEXT"
    if t <= {int, bool}:
        return "INTEGER"
    if t <= {int, float, bool}:
        return "REAL"
    return "TEXT"


def _norm(v):
    """Bind-safe value: JSON-encode lists/dicts, keep scalars as-is."""
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False)
    return v


class Acc:
    """Accumulates key -> set(python types)."""
    def __init__(self):
        self.types = {}

    def add(self, k, v):
        self.types.setdefault(k, set()).add(type(v))

    def update(self, d):
        if isinstance(d, dict):
            for k, v in d.items():
                self.add(k, v)

    def dedupe(self):
        """SQLite identifiers are case-insensitive — merge keys differing only by case."""
        seen = {}
        merged = {}
        for k, v in self.types.items():
            lk = k.lower()
            if lk in seen:
                merged[seen[lk]] |= v
            else:
                seen[lk] = k
                merged[k] = v
        self.types = merged

    def columns(self):
        return {k: sqltype(v) for k, v in self.types.items()}

    def keys(self):
        return set(self.types)


# ---------- key sets ----------

CVES_CORE = {"id", "sourceIdentifier", "published", "lastModified", "vulnStatus"}
CVES_CHILD = {"descriptions", "affected", "metrics", "weaknesses",
              "configurations", "references", "cveTags"}

AFFECTED_CHILD = {"versions", "modules", "cpes"}

VERSIONS_KEYS = {"version", "lessThan", "lessThanOrEqual", "versionType", "status"}
REFERENCE_KEYS = {"url", "source", "tags"}
CVSS_METRIC_KEYS = {"source", "type", "exploitabilityScore", "impactScore", "cvssData"}
SSVC_DATA_KEYS = {"timestamp", "id", "options", "role", "version"}
NODE_KEYS = {"operator", "negate", "cpeMatch"}


# ---------- prescan ----------

def prescan(data, acc):
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve") or {}
        acc["cves"].update({k: cve.get(k) for k in cve if k in CVES_CORE})

        for d in cve.get("descriptions") or []:
            acc["descriptions"].update(d)

        for t in cve.get("cveTags") or []:
            acc["cveTags"].update(t)

        for a in cve.get("affected") or []:
            for ad in a.get("affectedData") or []:
                acc["affected"].update(
                    {k: ad.get(k) for k in ad if k not in AFFECTED_CHILD})
                for ver in ad.get("versions") or []:
                    acc["affected_versions"].update(ver)

        for kind, arr in (cve.get("metrics") or {}).items():
            if not isinstance(arr, list):
                continue
            for m in arr:
                acc["cvss_metrics"].update({"metric_kind": kind})
                acc["cvss_metrics"].update(
                    {k: m.get(k) for k in m if k in CVSS_METRIC_KEYS})
                cd = m.get("cvssData")
                if isinstance(cd, dict):
                    acc["cvss_metrics"].update(cd)

                acc["ssvc_metrics"].update({"metric_kind": kind})
                sd = m.get("ssvcData")
                if isinstance(sd, dict):
                    for k in SSVC_DATA_KEYS:
                        if k in sd and k != "options":
                            acc["ssvc_metrics"].add(k, sd[k])
                    acc["ssvc_metrics"].add("source", m.get("source"))
                    for opt in sd.get("options") or []:
                        acc["ssvc_metrics"].update(opt)

        for w in cve.get("weaknesses") or []:
            acc["weaknesses"].update(
                {"source": w.get("source"), "type": w.get("type")})
            for dd in w.get("description") or []:
                acc["weaknesses"].update(dd)

        for r in cve.get("references") or []:
            acc["cve_references"].update(
                {k: r.get(k) for k in r if k in REFERENCE_KEYS})

        for c in cve.get("configurations") or []:
            for n in c.get("nodes") or []:
                acc["configuration_nodes"].update(
                    {k: n.get(k) for k in n if k in NODE_KEYS})
                for cm in n.get("cpeMatch") or []:
                    acc["cpe_matches"].update(cm)


# ---------- schema helpers ----------

def make_table(cur, name, cols: dict, unique=None):
    """Create table; unique index uses COALESCE so NULL == NULL for dedupe."""
    body = ",\n  ".join(f"{q(c)} {t}" for c, t in cols.items())
    cur.execute(f"CREATE TABLE IF NOT EXISTS {q(name)} (\n  {body}\n)")
    if unique:
        existing = set(cols.keys())
        idx_cols = [c for c in unique if c in existing]
        if len(idx_cols) == len(unique):
            idx_expr = ", ".join(f"COALESCE({q(c)}, '')" for c in idx_cols)
            cur.execute(
                f"CREATE UNIQUE INDEX IF NOT EXISTS {q('ux_' + name)} "
                f"ON {q(name)} ({idx_expr})"
            )


def build_cols(required: dict, extras: Acc, skip=()):
    """Start from required columns; append any *new* keys from the data,
    matching case-insensitively so SQLite doesn't reject duplicate names."""
    out = dict(required)
    lower_taken = {k.lower() for k in out}
    extras_cols = extras.columns()
    for c in sorted(extras.keys()):
        if c in skip:
            continue
        if c.lower() in lower_taken:
            continue
        out[c] = extras_cols[c]
        lower_taken.add(c.lower())
    out["_extra_json"] = "TEXT"
    return out


def insert(cur, table, row):
    """INSERT OR IGNORE. Returns True iff a *new* row was actually written.

    Every value passes through _norm() so lists/dicts are JSON-encoded and
    never reach sqlite3's binder as-is.
    """
    cols = list(row.keys())
    vals = [_norm(row[c]) for c in cols]
    sql = (f"INSERT OR IGNORE INTO {q(table)} ("
           + ",".join(q(c) for c in cols)
           + ") VALUES (" + ",".join("?" * len(cols)) + ")")
    before = cur.connection.total_changes
    try:
        cur.execute(sql, vals)
    except sqlite3.ProgrammingError as e:
        # Name the offending column so failures are diagnosable.
        for c, v in zip(cols, vals):
            if not isinstance(v, (str, int, float, bytes, type(None))):
                print(f"  !! {table}.{c} has unsupported type "
                      f"{type(v).__name__}: {v!r}")
        raise e
    return cur.connection.total_changes > before


# ---------- main ----------

def main():
    paths = sorted(glob.glob(os.path.join(DIR, "*.json")))
    datasets = []
    for p in paths:
        try:
            with open(p, encoding="utf-8") as fh:
                d = json.load(fh)
        except Exception as e:
            print(f"[skip] {os.path.basename(p)}: {e}")
            continue
        if not isinstance(d, dict) or "vulnerabilities" not in d:
            print(f"[skip] {os.path.basename(p)}: not an NVD CVE 2.0 payload")
            continue
        datasets.append((os.path.basename(p), d))
        print(f"[+] {os.path.basename(p)}: "
              f"{len(d.get('vulnerabilities', []))} records")

    if not datasets:
        raise SystemExit("No NVD CVE JSON files found.")

    # ---- prescan union of keys/types ----
    acc = {k: Acc() for k in [
        "cves", "descriptions", "cveTags", "affected", "affected_versions",
        "cvss_metrics", "ssvc_metrics", "weaknesses", "cve_references",
        "configuration_nodes", "cpe_matches",
    ]}
    for _, d in datasets:
        prescan(d, acc)
    for a in acc.values():
        a.dedupe()

    # ---- column sets (each table declares its join keys explicitly) ----
    cves_cols = {"id": "TEXT PRIMARY KEY"}
    for c in ["sourceIdentifier", "published", "lastModified", "vulnStatus"]:
        cves_cols[c] = acc["cves"].columns().get(c, "TEXT")
    for c in sorted(acc["cves"].keys() - CVES_CORE - CVES_CHILD):
        cves_cols[c] = acc["cves"].columns()[c]
    cves_cols["_extra_json"] = "TEXT"

    descriptions_cols = build_cols(
        {"cve_id": "TEXT", "lang": "TEXT", "value": "TEXT"},
        acc["descriptions"],
    )

    cvetags_cols = build_cols(
        {"cve_id": "TEXT", "sourceIdentifier": "TEXT", "tags": "TEXT"},
        acc["cveTags"],
    )

    affected_cols = build_cols(
        {"cve_id": "TEXT", "source": "TEXT",
         "vendor": "TEXT", "product": "TEXT", "defaultStatus": "TEXT",
         "repo": "TEXT", "packageURL": "TEXT", "collectionURL": "TEXT",
         "packageName": "TEXT", "modules": "TEXT", "cpes": "TEXT"},
        acc["affected"], skip=AFFECTED_CHILD,
    )

    affected_versions_cols = build_cols(
        {"affected_row_id": "INTEGER", "version": "TEXT",
         "lessThan": "TEXT", "lessThanOrEqual": "TEXT",
         "versionType": "TEXT", "status": "TEXT"},
        acc["affected_versions"], skip=VERSIONS_KEYS,
    )

    cvss_cols = build_cols(
        {"cve_id": "TEXT", "metric_kind": "TEXT", "source": "TEXT",
         "type": "TEXT", "exploitabilityScore": "REAL", "impactScore": "REAL"},
        acc["cvss_metrics"],
    )

    ssvc_cols = build_cols(
        {"cve_id": "TEXT", "metric_kind": "TEXT", "source": "TEXT",
         "timestamp": "TEXT", "id": "TEXT", "role": "TEXT", "version": "TEXT"},
        acc["ssvc_metrics"],
    )

    weaknesses_cols = build_cols(
        {"cve_id": "TEXT", "source": "TEXT", "type": "TEXT",
         "lang": "TEXT", "value": "TEXT"},
        acc["weaknesses"],
    )

    cve_refs_cols = build_cols(
        {"cve_id": "TEXT", "url": "TEXT", "source": "TEXT", "tags": "TEXT"},
        acc["cve_references"],
    )

    nodes_cols = build_cols(
        {"cve_id": "TEXT", "config_index": "INTEGER", "node_index": "INTEGER",
         "operator": "TEXT", "negate": "INTEGER"},
        acc["configuration_nodes"], skip=NODE_KEYS,
    )

    cpematch_cols = build_cols(
        {"node_row_id": "INTEGER",
         "vulnerable": "INTEGER", "criteria": "TEXT",
         "versionStartIncluding": "TEXT", "versionEndIncluding": "TEXT",
         "versionStartExcluding": "TEXT", "versionEndExcluding": "TEXT",
         "matchCriteriaId": "TEXT"},
        acc["cpe_matches"],
    )

    # ---- open DB, drop & recreate schema ----
    conn = sqlite3.connect(os.path.join(DIR, DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    cur = conn.cursor()

    cur.executescript("""
    DROP TABLE IF EXISTS cpe_matches;
    DROP TABLE IF EXISTS configuration_nodes;
    DROP TABLE IF EXISTS cve_references;
    DROP TABLE IF EXISTS weaknesses;
    DROP TABLE IF EXISTS ssvc_metrics;
    DROP TABLE IF EXISTS cvss_metrics;
    DROP TABLE IF EXISTS affected_versions;
    DROP TABLE IF EXISTS affected;
    DROP TABLE IF EXISTS cveTags;
    DROP TABLE IF EXISTS descriptions;
    DROP TABLE IF EXISTS cve_source_files;
    DROP TABLE IF EXISTS cves;
    DROP TABLE IF EXISTS source_files;
    """)

    cur.execute("""
    CREATE TABLE source_files (
        file_id        INTEGER PRIMARY KEY AUTOINCREMENT,
        filename       TEXT UNIQUE,
        resultsPerPage INTEGER,
        startIndex     INTEGER,
        totalResults   INTEGER,
        format         TEXT,
        version        TEXT,
        timestamp      TEXT
    )""")

    make_table(cur, "cves", cves_cols)

    cur.execute("""
    CREATE TABLE cve_source_files (
        cve_id  TEXT NOT NULL,
        file_id INTEGER NOT NULL,
        PRIMARY KEY (cve_id, file_id)
    )""")

    make_table(cur, "descriptions", descriptions_cols,
               unique=["cve_id", "lang"])
    make_table(cur, "cveTags", cvetags_cols,
               unique=["cve_id", "sourceIdentifier"])
    make_table(cur, "affected", affected_cols,
               unique=["cve_id", "vendor", "product", "packageURL"])
    make_table(cur, "affected_versions", affected_versions_cols,
               unique=["affected_row_id", "version", "lessThan",
                       "lessThanOrEqual", "versionType", "status"])
    make_table(cur, "cvss_metrics", cvss_cols,
               unique=["cve_id", "metric_kind", "source", "type",
                       "vectorString"])
    make_table(cur, "ssvc_metrics", ssvc_cols,
               unique=["cve_id", "metric_kind", "source"])
    make_table(cur, "weaknesses", weaknesses_cols,
               unique=["cve_id", "source", "value"])
    make_table(cur, "cve_references", cve_refs_cols,
               unique=["cve_id", "url", "source"])
    make_table(cur, "configuration_nodes", nodes_cols,
               unique=["cve_id", "config_index", "node_index"])
    make_table(cur, "cpe_matches", cpematch_cols,
               unique=["node_row_id", "criteria", "matchCriteriaId"])

    def extra_json(d, consumed):
        x = {k: v for k, v in d.items() if k not in consumed}
        return json.dumps(x, ensure_ascii=False) if x else None

    # ---- load ----
    for filename, data in datasets:
        cur.execute(
            "INSERT OR IGNORE INTO source_files "
            "(filename, resultsPerPage, startIndex, totalResults, "
            " format, version, timestamp) "
            "VALUES (?,?,?,?,?,?,?)",
            (filename, data.get("resultsPerPage"), data.get("startIndex"),
             data.get("totalResults"), data.get("format"),
             data.get("version"), data.get("timestamp")),
        )
        file_id = cur.execute(
            "SELECT file_id FROM source_files WHERE filename=?",
            (filename,)
        ).fetchone()[0]

        for v in data.get("vulnerabilities", []):
            cve = v.get("cve") or {}
            cve_id = cve.get("id")
            if not cve_id:
                continue

            # ---- cves ----
            row = {"id": cve_id}
            for c in cves_cols:
                if c in ("id", "_extra_json"):
                    continue
                row[c] = cve.get(c)
            row["_extra_json"] = extra_json(cve, CVES_CORE | CVES_CHILD)
            insert(cur, "cves", row)

            insert(cur, "cve_source_files",
                   {"cve_id": cve_id, "file_id": file_id})

            # ---- descriptions ----
            for d in cve.get("descriptions") or []:
                row = {}
                for c in descriptions_cols:
                    if c in ("cve_id", "_extra_json"):
                        continue
                    row[c] = d.get(c)
                row["cve_id"] = cve_id
                row["_extra_json"] = extra_json(d, {"lang", "value"})
                insert(cur, "descriptions", row)

            # ---- cveTags ----
            for t in cve.get("cveTags") or []:
                row = {}
                for c in cvetags_cols:
                    if c in ("cve_id", "_extra_json"):
                        continue
                    row[c] = t.get(c)
                row["cve_id"] = cve_id
                row["_extra_json"] = extra_json(
                    t, {"sourceIdentifier", "tags"})
                insert(cur, "cveTags", row)

            # ---- affected + affected_versions ----
            for a in cve.get("affected") or []:
                src = a.get("source")
                for ad in a.get("affectedData") or []:
                    row = {}
                    for c in affected_cols:
                        if c in ("cve_id", "source", "_extra_json"):
                            continue
                        row[c] = ad.get(c)
                    row["cve_id"] = cve_id
                    row["source"] = src
                    row["_extra_json"] = extra_json(
                        ad, AFFECTED_CHILD | set(affected_cols))

                    was_inserted = insert(cur, "affected", row)
                    if was_inserted:
                        affected_id = cur.lastrowid
                    else:
                        affected_id = cur.execute(
                            "SELECT rowid FROM affected WHERE "
                            "cve_id = ? AND "
                            "COALESCE(vendor, '')    = COALESCE(?, '') AND "
                            "COALESCE(product, '')   = COALESCE(?, '') AND "
                            "COALESCE(packageURL, '')= COALESCE(?, '')",
                            (cve_id, ad.get("vendor"), ad.get("product"),
                             ad.get("packageURL")),
                        ).fetchone()[0]

                    for ver in ad.get("versions") or []:
                        vrow = {}
                        for c in affected_versions_cols:
                            if c in ("affected_row_id", "_extra_json"):
                                continue
                            vrow[c] = ver.get(c)
                        vrow["affected_row_id"] = affected_id
                        vrow["_extra_json"] = extra_json(ver, VERSIONS_KEYS)
                        insert(cur, "affected_versions", vrow)

            # ---- metrics (CVSS + SSVC) ----
            for kind, arr in (cve.get("metrics") or {}).items():
                if not isinstance(arr, list):
                    continue
                for m in arr:
                    if isinstance(m.get("cvssData"), dict):
                        cd = m["cvssData"]
                        row = {}
                        for c in cvss_cols:
                            if c in ("cve_id", "metric_kind", "source",
                                     "type", "_extra_json"):
                                continue
                            row[c] = cd.get(c)
                        row["cve_id"] = cve_id
                        row["metric_kind"] = kind
                        row["source"] = m.get("source")
                        row["type"] = m.get("type")
                        row["_extra_json"] = extra_json(cd, set(cvss_cols))
                        insert(cur, "cvss_metrics", row)

                    if isinstance(m.get("ssvcData"), dict):
                        sd = m["ssvcData"]
                        row = {}
                        for c in ssvc_cols:
                            if c in ("cve_id", "metric_kind", "source",
                                     "_extra_json"):
                                continue
                            row[c] = sd.get(c)
                        for opt in sd.get("options") or []:
                            for ok, ov in opt.items():
                                if ok in ssvc_cols:
                                    row[ok] = ov
                        row["cve_id"] = cve_id
                        row["metric_kind"] = kind
                        row["source"] = m.get("source")
                        row["_extra_json"] = extra_json(
                            sd, set(ssvc_cols) | {"options"})
                        insert(cur, "ssvc_metrics", row)

            # ---- weaknesses ----
            for w in cve.get("weaknesses") or []:
                for dd in w.get("description") or []:
                    row = {}
                    for c in weaknesses_cols:
                        if c in ("cve_id", "source", "type", "_extra_json"):
                            continue
                        row[c] = dd.get(c)
                    row["cve_id"] = cve_id
                    row["source"] = w.get("source")
                    row["type"] = w.get("type")
                    row["_extra_json"] = extra_json(dd, {"lang", "value"})
                    insert(cur, "weaknesses", row)

            # ---- references ----
            for r in cve.get("references") or []:
                row = {}
                for c in cve_refs_cols:
                    if c in ("cve_id", "_extra_json"):
                        continue
                    row[c] = r.get(c)
                row["cve_id"] = cve_id
                row["_extra_json"] = extra_json(
                    r, {"url", "source", "tags"})
                insert(cur, "cve_references", row)

            # ---- configurations -> nodes -> cpe_matches ----
            for ci, cfg in enumerate(cve.get("configurations") or []):
                for ni, node in enumerate(cfg.get("nodes") or []):
                    nrow = {}
                    for c in nodes_cols:
                        if c in ("cve_id", "config_index", "node_index",
                                 "_extra_json"):
                            continue
                        nrow[c] = node.get(c)
                    nrow["cve_id"] = cve_id
                    nrow["config_index"] = ci
                    nrow["node_index"] = ni
                    nrow["_extra_json"] = extra_json(node, NODE_KEYS)

                    was_inserted = insert(cur, "configuration_nodes", nrow)
                    if was_inserted:
                        node_id = cur.lastrowid
                    else:
                        node_id = cur.execute(
                            "SELECT rowid FROM configuration_nodes "
                            "WHERE cve_id=? AND config_index=? AND node_index=?",
                            (cve_id, ci, ni),
                        ).fetchone()[0]

                    for cm in node.get("cpeMatch") or []:
                        crow = {}
                        for c in cpematch_cols:
                            if c in ("node_row_id", "_extra_json"):
                                continue
                            crow[c] = cm.get(c)
                        crow["node_row_id"] = node_id
                        crow["_extra_json"] = extra_json(
                            cm, set(cpematch_cols))
                        insert(cur, "cpe_matches", crow)

    conn.commit()

    # ---- summary ----
    print(f"\nDB: {os.path.join(DIR, DB_PATH)}")
    tables = [r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    print(f"\n{'table':<24}{'rows':>8}")
    print("-" * 34)
    for t in tables:
        n = cur.execute(f"SELECT COUNT(*) FROM {q(t)}").fetchone()[0]
        print(f"{t:<24}{n:>8}")

    # ---- integrity / orphan checks ----
    print("\nIntegrity checks:")
    checks = [
        ("orphan cve_source_files",
         "SELECT COUNT(*) FROM cve_source_files j "
         "LEFT JOIN cves c ON c.id = j.cve_id WHERE c.id IS NULL"),
        ("orphan descriptions",
         "SELECT COUNT(*) FROM descriptions d "
         "LEFT JOIN cves c ON c.id = d.cve_id WHERE c.id IS NULL"),
        ("orphan cveTags",
         "SELECT COUNT(*) FROM cveTags t "
         "LEFT JOIN cves c ON c.id = t.cve_id WHERE c.id IS NULL"),
        ("orphan affected",
         "SELECT COUNT(*) FROM affected a "
         "LEFT JOIN cves c ON c.id = a.cve_id WHERE c.id IS NULL"),
        ("orphan affected_versions",
         "SELECT COUNT(*) FROM affected_versions av "
         "LEFT JOIN affected a ON a.rowid = av.affected_row_id "
         "WHERE a.rowid IS NULL"),
        ("orphan cvss_metrics",
         "SELECT COUNT(*) FROM cvss_metrics m "
         "LEFT JOIN cves c ON c.id = m.cve_id WHERE c.id IS NULL"),
        ("orphan ssvc_metrics",
         "SELECT COUNT(*) FROM ssvc_metrics m "
         "LEFT JOIN cves c ON c.id = m.cve_id WHERE c.id IS NULL"),
        ("orphan weaknesses",
         "SELECT COUNT(*) FROM weaknesses w "
         "LEFT JOIN cves c ON c.id = w.cve_id WHERE c.id IS NULL"),
        ("orphan cve_references",
         "SELECT COUNT(*) FROM cve_references r "
         "LEFT JOIN cves c ON c.id = r.cve_id WHERE c.id IS NULL"),
        ("orphan configuration_nodes",
         "SELECT COUNT(*) FROM configuration_nodes n "
         "LEFT JOIN cves c ON c.id = n.cve_id WHERE c.id IS NULL"),
        ("orphan cpe_matches",
         "SELECT COUNT(*) FROM cpe_matches m "
         "LEFT JOIN configuration_nodes n ON n.rowid = m.node_row_id "
         "WHERE n.rowid IS NULL"),
        ("cves without descriptions",
         "SELECT COUNT(*) FROM cves c "
         "WHERE NOT EXISTS (SELECT 1 FROM descriptions d "
         "                  WHERE d.cve_id = c.id)"),
        ("cves without any metrics",
         "SELECT COUNT(*) FROM cves c WHERE NOT EXISTS ("
         " SELECT 1 FROM cvss_metrics m WHERE m.cve_id = c.id"
         " UNION ALL "
         " SELECT 1 FROM ssvc_metrics m WHERE m.cve_id = c.id)"),
    ]
    for name, sql in checks:
        n = cur.execute(sql).fetchone()[0]
        status = "OK" if n == 0 else f"!! {n} rows"
        print(f"  {name:<35}{status}")

    print("\nPRAGMA integrity_check:")
    print("  " + cur.execute("PRAGMA integrity_check").fetchone()[0])

    conn.close()


if __name__ == "__main__":
    main()