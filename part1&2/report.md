# AI Security Research — Data Reduction Analysis

**Project:** `AI_Security_Research`
**Analyzed:** 2026-11-12
**Scope:** `part1&2` (SQLite pipeline) + `part3` (analysis/plot pipeline)

---

## TL;DR

| Question                                                   | Answer                               |
|------------------------------------------------------------|--------------------------------------|
| How many **CVEs** were dropped from start to end?          | **23 CVEs** (882 → 859)              |
| How many **flat rows** were dropped in part3?              | **77 rows** (894 → 817)              |
| **Total rows** removed across all filtering stages         | **100 rows** (23 + 77)               |
| Rows dropped by the flattening step (`cves` → `cves_flat`) | **0** (only fan-out duplication, §3) |
| Rows that ended up in the final plot                       | **817**                              |

> ⚠️ **The 100 is not "100 CVEs."** It is 23 CVEs (part1&2) + 77 flat rows (part3). These are different units. If your question is strictly *"how many CVEs did we lose?"*, the answer is **23**.

---

## 1. Pipeline Overview

```
nvd_cve_backup1.db          (882 CVEs)   ← starting point
        │
        │  part1&2 filters (metric/scope cleanup)
        ▼
nvd_cve.db                  (859 CVEs)   ← −23 CVEs
        │
        │  cves → cves_flat (flatten; 35 CVEs duplicate ×2)
        ▼
cves_flat / genai_cves_cvss31.csv  (894 flat rows)   ← +35 fan-out, 0 drops
        │
        │  part3: df[df['C'].notna()]                  ← −36 flat rows
        ▼
                                (858 flat rows)
        │
        │  part3: group.isin(main_groups)              ← −41 flat rows
        ▼
Final plot dataset          (817 flat rows)
```

---

## 2. Part 1 & 2 — CVE-level drops

### 2.1 Row counts across all databases

| DB file                  | `cves` rows | Δ vs previous |
|--------------------------|------------:|--------------:|
| `nvd_cve_backup1.db`     |         882 |   — *(start)* |
| `nvd_cve_backup2.db`     |         881 |            −1 |
| `nvd_cve_backup3.db`     |         859 |       **−22** |
| `nvd_cve_backup4.db`     |         859 |             0 |
| `nvd_cve_backup5.db`     |         859 |             0 |
| `nvd_cve_backup6.db`     |         859 |             0 |
| `nvd_cve_backup7.db`     |         859 |             0 |
| `nvd_cve_backup8.db`     |         859 |             0 |
| `nvd_cve_backup9.db`     |         859 |             0 |
| **`nvd_cve.db` (final)** |     **859** |             0 |

### 2.2 Findings

- **Total CVEs removed: 23** (882 → 859).
- **All 23 drops happened before `backup3`:**
  - `backup1 → backup2`: −1 CVE
  - `backup2 → backup3`: −22 CVEs
- **`backup3` → `nvd_cve.db`: no change in row count.** `backup8`, `backup9`, and `nvd_cve.db` are byte-identical (4,653,056 bytes).
- Removal performed by metric/scope filters (`remove_without_metrics_cves.py`, `cleanup_scope.py`), which strip CVEs lacking CVSS/SSVC metrics or falling outside the analyzed CPE scope.

### 2.3 Schema

```sql
CREATE TABLE "cves" (
  "id"               TEXT PRIMARY KEY,
  "sourceIdentifier" TEXT,
  "published"        TEXT,
  "lastModified"     TEXT,
  "vulnStatus"       TEXT,
  "_extra_json"      TEXT
);
```

---

## 3. Flattening Step — `cves` → `cves_flat`

### 3.1 Coverage check

```
cves_total              : 859
flat_distinct_cve       : 859
flat_matched (in cves)  : 859
cves_missing_from_flat  :   0
```

**No CVE was lost during flattening.** Every CVE in `cves` appears at least once in `cves_flat`.

### 3.2 Fan-out distribution

| Rows per CVE | Number of CVEs | Total rows |
|-------------:|---------------:|-----------:|
|            1 |            824 |        824 |
|            2 |             35 |         70 |
|    **Total** |        **859** |    **894** |

**Interpretation:** 35 CVEs produce 2 flat rows each (multiple CWE / product / advisory entries). This produces **+35 rows** — a *fan-out*, not a drop. The CSV `genai_cves_cvss31.csv` (894 data rows) is therefore a superset in row count, not a subset.

> **This is why 894 > 859 is not a contradiction.**

---

## 4. Part 3 — Flat-row drops

### 4.1 Filters in `analyze_rq6.py`

```python
df    = pd.read_sql("SELECT * FROM cves_flat", conn)   # 894 rows (written to CSV)

valid = df[df["C"].notna()].copy()                     # filter #1 — drop C-null rows

main_groups = ["Langflow", "Open WebUI", "Flowise", "vLLM",
               "LangChain", "Ollama", "AutoGPT"]

t1    = valid[valid["group"].isin(main_groups)]        # filter #2 — keep 7 groups
```

### 4.2 Step-by-step row accounting

| Step                                        |    Rows |       Δ |
|---------------------------------------------|--------:|--------:|
| `0.` Raw CSV (`cves_flat`)                  | **894** |       — |
| `1.` After `df[df['C'].notna()]`            | **858** | **−36** |
| `2.` After `valid[group.isin(main_groups)]` | **817** | **−41** |
| **Total dropped in part3**                  |         | **−77** |

**Proportional drop in part3: 77 / 894 = 8.6 %.**

### 4.3 Drop #1 — rows with `C is null` (36 rows)

| Group       | Rows dropped |
|-------------|-------------:|
| LangChain   |            9 |
| AutoGPT     |            8 |
| Langflow    |            6 |
| Ollama      |            4 |
| Flowise     |            4 |
| vLLM        |            2 |
| LlamaIndex  |            1 |
| LangChain4j |            1 |
| CrewAI      |            1 |
| **Total**   |       **36** |

33 of the 36 belong to *kept* groups (they would have appeared in the chart but lack a CIA Confidentiality rating). The other 3 belong to non-main groups and would have been dropped by filter #2 anyway.

### 4.4 Drop #2 — groups outside the 7 analyzed (41 rows)

| Group              | Rows dropped |
|--------------------|-------------:|
| CrewAI             |           11 |
| LangChain-ChatChat |            9 |
| LangChain4j        |            5 |
| LlamaIndex         |            4 |
| GPT-SoVITS         |            3 |
| MLflow             |            2 |
| LoLLMs             |            1 |
| Portkey            |            1 |
| AutoGen / AG2      |            1 |
| Flexible-GraphRAG  |            1 |
| KubeAI             |            1 |
| mem0               |            1 |
| LightRAG           |            1 |
| **Total**          |       **41** |

### 4.5 Kept — 817 rows across 7 groups

| Group      | Rows kept (n=) |
|------------|---------------:|
| Langflow   |            230 |
| Open WebUI |            167 |
| Flowise    |            147 |
| vLLM       |            135 |
| LangChain  |             71 |
| Ollama     |             39 |
| AutoGPT    |             28 |
| **Total**  |        **817** |

These values should exactly match the `(n=…)` labels on `rq6_cia_stacked_bar (2).png`.

---

## 5. Final Consolidated Ledger

| Stage                              | Unit        | Input |  Output | Dropped | Reason                                    |
|------------------------------------|-------------|------:|--------:|--------:|-------------------------------------------|
| **part1&2 — metrics/scope filter** | CVEs        |   882 |     859 | **−23** | No CVSS/SSVC metric, or outside CPE scope |
| **flatten** (`cves` → `cves_flat`) | CVEs → rows |   859 |     894 |   **0** | Fan-out only (35 CVEs → 70 rows); no loss |
| **part3 — CIA filter**             | flat rows   |   894 |     858 | **−36** | `C` (Confidentiality) is null             |
| **part3 — group filter**           | flat rows   |   858 |     817 | **−41** | Group not in 7 analyzed groups            |
| **End state**                      | flat rows   |     — | **817** |         | Plotted                                   |

### Total drops

- **23 CVEs** removed (part1&2)
- **77 flat rows** removed (part3: 36 + 41)
- **100 rows** removed in row-count terms (23 + 77)

---

## 6. Reproducibility — Commands Used

Run from `/home/hosein/PycharmProjects/AI_Security_Research`.

### 6.1 Part1&2 — count `cves` per DB

```bash
BASE='/home/hosein/PycharmProjects/AI_Security_Research/part1&2'
shopt -s nullglob
for db in "$BASE"/nvd_cve.db "$BASE"/nvd_cve_backup*.db; do
    n=$(sqlite3 "$db" "SELECT COUNT(*) FROM cves;")
    printf "%-20s : %s\n" "$(basename "$db")" "$n"
done
shopt -u nullglob
```

### 6.2 Flatten coverage check

```bash
BASE='/home/hosein/PycharmProjects/AI_Security_Research/part1&2'
sqlite3 "$BASE/nvd_cve.db" "
  SELECT
    (SELECT COUNT(*) FROM cves)                                        AS cves_total,
    (SELECT COUNT(DISTINCT cve_id) FROM cves_flat)                     AS flat_distinct_cve,
    (SELECT COUNT(DISTINCT cve_id) FROM cves_flat WHERE cve_id IN
        (SELECT id FROM cves))                                         AS flat_matched,
    (SELECT COUNT(*) FROM cves WHERE id NOT IN
        (SELECT DISTINCT cve_id FROM cves_flat))                       AS cves_missing_from_flat;"
```

### 6.3 Fan-out distribution

```bash
BASE='/home/hosein/PycharmProjects/AI_Security_Research/part1&2'
sqlite3 -header -column "$BASE/nvd_cve.db" "
  SELECT rows_per_cve, COUNT(*) AS num_cves,
         rows_per_cve * COUNT(*) AS total_rows
  FROM (SELECT cve_id, COUNT(*) AS rows_per_cve FROM cves_flat GROUP BY cve_id)
  GROUP BY rows_per_cve ORDER BY rows_per_cve;"
```

### 6.4 Part3 — replay filters and count drops

```bash
python3 - <<'PY'
import pandas as pd
p = '/home/hosein/PycharmProjects/AI_Security_Research/part3/genai_cves_cvss31.csv'
df = pd.read_csv(p, low_memory=False)

main_groups = ["Langflow", "Open WebUI", "Flowise", "vLLM",
               "LangChain", "Ollama", "AutoGPT"]

total = len(df)
valid = df[df["C"].notna()]
t1    = valid[valid["group"].isin(main_groups)]

print(f"0. raw CSV rows                 : {total}")
print(f"1. after  df['C'].notna()       : {len(valid)}  (dropped {total-len(valid)})")
print(f"2. after  group in 7            : {len(t1)}   (dropped {len(valid)-len(t1)})")
print(f"→ total dropped in part3        : {total-len(t1)}  ({(total-len(t1))/total:.1%})")
print()
print("drop #1 by group:")
print(df[df["C"].isna()]["group"].value_counts(dropna=False).to_string())
print()
print("drop #2 by group:")
print(valid[~valid["group"].isin(main_groups)]["group"].value_counts(dropna=False).to_string())
print()
print("kept per group:")
print(t1["group"].value_counts().to_string())
PY
```

---

## 7. Caveats

1. **"Total drop" depends on unit.** 23 CVEs vs. 77 flat rows vs. 100 combined. There is no single unambiguous "total" — the two stages operate on different entities.
2. **`+35` is not a drop.** It is a fan-out increasing row count from 859 to 894. Included only to explain why the CSV has more rows than the `cves` table.
3. **Part3's drops are *within the analysis*, not from the DB.** `nvd_cve.db` still contains all 859 CVEs and all 894 flat rows — the 77 "dropped" rows are only excluded from the RQ6 plot; they are not deleted from any database or CSV.
4. **`backup8`, `backup9`, and `nvd_cve.db` are identical.** No data changes after `backup3` in `cves`. Later backups add/populate auxiliary tables (`epss`, `advisory_url`, `cve_products`) but do not change `cves` membership.

---

## 8. One-Line Answer

> **Across the whole pipeline, 23 CVEs were removed in part1&2 (882 → 859), and 77 flat rows were removed in part3 (894 → 817). Combined that is 100 rows, though only 23 represent actual CVE loss — the remaining 77 are analysis-scope exclusions from the plot dataset.**