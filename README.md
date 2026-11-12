# AI Security Research

A multi-stage research pipeline that collects, cleans, analyzes, and publishes
data about security vulnerabilities (CVEs) in GenAI / LLM tooling.

The project is split into five sequential parts. Each part has one job and
feeds its output into the next.

---

## Directory Structure

```
AI_Security_Research/
├── part1&2/    → Data collection + cleaning
├── part3/      → Data analysis
├── part4/      → LinkedIn post text
└── part5/      → LinkedIn post images
```

---

## Part 1 — Data Gathering

**Directory:** `part1&2/` (shared with Part 2)

Fetches raw CVE data from public sources (NVD, EPSS, and project-specific
advisories) and stores it in a SQLite database.

**Key files:**
- `all_genai_cves_raw.json` — raw NVD response dump
- `*_cve_data.json` — per-project CVE lists (LangChain, Langflow, Ollama, vLLM, Flowise, CrewAI, AutoGen, AutoGPT, Open WebUI, LlamaIndex)
- `nvd_cve_backup1.db` … `nvd_cve_backup9.db` — incremental snapshots taken during collection and cleaning
- `fetch_epss.py` — pulls EPSS scores for each CVE
- `save_to_db.py` — writes fetched data into SQLite

**Output:** a populated `nvd_cve.db` with the raw `cves`, `cvss_metrics`, `ssvc_metrics`, `epss`, `products`, `weaknesses`, etc.

---

## Part 2 — Data Cleaning & Filtering

**Directory:** `part1&2/` (shared with Part 1)

Trims the raw dataset down to the CVEs that are actually in scope: CVEs that
have CVSS / SSVC metrics and belong to the analyzed products. CVEs that lack
the required metric data or fall outside the project scope are removed.

**Key files:**
- `remove_without_metrics_cves.py` — drops CVEs with no metric data
- `find_without_metric_cves.py` — diagnostic listing of metric-less CVEs
- `cleanup_scope.py` — removes CVEs outside the analyzed CPE scope
- `audit_scope.py` — sanity check on scope filtering
- `build_cve_products.py`, `build_products.py`, `build_flat.py` — build the flat analysis views (`cves_flat`, `cve_products`)
- `nvd_cve.db` — final cleaned database used by later parts

**Output:** `nvd_cve.db` with 859 in-scope CVEs (down from 882 in the raw snapshot — 23 dropped).

---

## Part 3 — Data Analysis

**Directory:** `part3/`

Reads the cleaned DB and produces the analysis artifacts used for the write-up.

**Key files:**
- `analyze_rq6.py` — runs the RQ6 analysis and produces the chart
- `genai_cves_cvss31.csv` — flat analysis export (CVSS 3.1 / CIA / EPSS per CVE, 894 rows)
- `rq6_cia_stacked_bar (2).png` — the RQ6 stacked-bar chart (CIA impact distribution across the 7 main groups)

**What it does:**
1. Loads `cves_flat` from the cleaned DB
2. Filters rows without a CIA confidentiality rating
3. Keeps only the 7 main analyzed groups (Langflow, Open WebUI, Flowise, vLLM, LangChain, Ollama, AutoGPT)
4. Builds the stacked-bar chart of C / I / A impact distribution

**Output:** a CSV and a PNG ready to be embedded in the report / LinkedIn post.

---

## Part 4 — LinkedIn Post Text

**Directory:** `part4/`

Holds the written text of the LinkedIn post(s) derived from the Part 3 results.

**Key files:**
- `english.md` — English version of the post
- `persian.md` — Persian version of the post

**Output:** ready-to-publish copy for LinkedIn.

---

## Part 5 — LinkedIn Post Images

**Directory:** `part5/`

Holds the final images (charts, infographics, or screenshots) that accompany
the Part 4 post text on LinkedIn.

**Output:** image assets used in the published post.

---

## End-to-End Flow

```
Part 1: fetch CVEs
    ↓
Part 2: filter out CVEs with no metrics / out of scope
    ↓
Part 3: flatten + filter + chart (RQ6 CIA stacked bar)
    ↓
Part 4: write the LinkedIn post (EN + FA)
    ↓
Part 5: build the LinkedIn post images
```

---

## Data Reduction Summary

Across the pipeline, the dataset shrinks at each filtering step:

| Stage                                   | Unit        | Start |     End |         Dropped |
|-----------------------------------------|-------------|------:|--------:|----------------:|
| Part 1 & 2 — metric/scope filter        | CVEs        |   882 |     859 |         **−23** |
| Part 2 — flatten (`cves` → `cves_flat`) | CVEs → rows |   859 |     894 | 0 (fan-out +35) |
| Part 3 — CIA filter (drop C-null)       | flat rows   |   894 |     858 |         **−36** |
| Part 3 — group filter (keep 7 groups)   | flat rows   |   858 |     817 |         **−41** |
| **Final plotted dataset**               | flat rows   |     — | **817** |                 |

- **CVEs lost from the pipeline:** 23
- **Flat rows excluded from the final chart:** 77
- **Total rows removed:** 100