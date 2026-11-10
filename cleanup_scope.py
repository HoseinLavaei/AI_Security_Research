"""
Remove CVEs from nvd_cve.db that are NOT related to Generative AI / LLM tools.

Keep criteria (evaluated in order, first hit wins):
  0. CVE id is in DENY_CVE_IDS                          (forced delete)
  1. CPE vendor:product pair in KEEP_VENDOR_PRODUCT_PAIRS (very specific keep)
  2. CPE product name in KEEP_PRODUCTS                    (strong keep)
  3. packageURL matches GENAI_PURL_SUBSTRINGS
  4. affected vendor/product: pair in KEEP_VENDOR_PRODUCT_PAIRS,
     or product in KEEP_PRODUCTS
  5. English description matches GENAI_DESC_KEYWORDS      (last resort)

Delete otherwise.

Default: dry-run. Pass --apply to actually delete.
Add --list-keep to also dump what was kept and why.
"""

import argparse
import os
import re
import sqlite3
import sys

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nvd_cve.db")

# ---------------------------------------------------------------------------
# Allowlists / denylists — edit these and re-run.
# ---------------------------------------------------------------------------

# Explicitly forced-delete regardless of any keep signal.
# Use this for false positives that slip through the description fallback.
DENY_CVE_IDS = {
    "CVE-2026-43625": "CodexBar (menu-bar usage app, not GenAI infra)",
    "CVE-2026-61732": "Decepticon (red-team hacking agent)",
    "CVE-2026-33401": "Wallos (subscription tracker, not GenAI)",
    "CVE-2025-58177": "n8n (workflow automation, 'langchain' keyword leak)",
    "CVE-2026-119408": "n8n (workflow automation, 'langchain' keyword leak)",
}

# Vendor:product pairs (normalized) that are GenAI-specific.
# Checked BEFORE the bare product-name list, so reasons are precise.
KEEP_VENDOR_PRODUCT_PAIRS = {
    # flowiseai:embed — 'embed' alone is far too generic to allowlist globally
    ("flowiseai", "embed"),
}

# Product names (normalized: lowercase, alnum only). Any CPE or affected.product
# whose normalized form is in this set is treated as GenAI/LLM.
KEEP_PRODUCTS = {
    # ----- the 7 named tools -----
    "autogpt", "autogptplatform", "autogptclassic",
    "langchain", "langchainexperimental", "langchaincore",
    "langchaincommunity", "langchainopenai", "langchaintextsplitters",
    "langchainjs", "langsmith", "langgraph", "langchainmongodb",
    "langgraphcheckpointmongodb", "langgraphstoremongodb",
    "langsmithsdk",
    "ollama", "ollamamcp",
    "vllm", "vllmhardware", "vllmorchestratorgateway",
    "openwebui",
    "flowise", "flowisecomponents",
    "langflow", "langflowdesktop", "langflowbase", "langflowoss",

    # ----- other GenAI / LLM tools present in the corpus -----
    "llamaindex",
    "crewai", "crewaitools",
    "ag2", "autogen",
    "langchainchatchat", "langchainchatglmwebui",
    "gptsovitswebui",
    "lollmswebui",
    "mlflow",
    "kubeai",
    "flexiblegraphrag",
    "mem0",
    "lightrag",
    "nuxtollama",
    "langchain4j", "langchain4jaideepin", "langchaingo",
    "portkeyai", "portkeyaigateway",
}

# purl substrings (lowercased) — matched via plain substring.
GENAI_PURL_SUBSTRINGS = {
    "pkg:npm/flowise", "pkg:npm/flowise-components", "pkg:pypi/flowise",
    "pkg:pypi/open-webui", "pkg:pypi/open_webui",
    "pkg:pypi/vllm", "pkg:github/vllm-project",
    "pkg:golang/github.com/ollama/ollama",
    "pkg:pypi/langchain", "pkg:npm/langchain",
    "pkg:pypi/langgraph", "pkg:npm/langgraph",
    "pkg:pypi/langsmith", "pkg:npm/langsmith",
    "pkg:pypi/langflow", "pkg:github/langflow-ai",
    "pkg:github/flowiseai",
    "pkg:pypi/llama_index", "pkg:pypi/llamaindex",
    "pkg:pypi/crewai", "pkg:pypi/crewai-tools",
    "pkg:pypi/ag2", "pkg:pypi/autogen",
    "pkg:pypi/mlflow",
    "pkg:pypi/mem0ai",
    "pkg:pypi/lightrag",
    "pkg:pypi/langchain-chatchat",
    "pkg:github/langchain-ai/langchain",
    "pkg:github/langchain-ai/langchainjs",
    "pkg:github/langchain-ai/langgraph",
    "pkg:github/langchain-ai/langsmith-sdk",
    "pkg:github/langchain-ai/langchain-mongodb",
    "pkg:github/langchain-ai/langgraph-checkpoint-mongodb",
    "pkg:github/langchain-ai/langgraph-store-mongodb",
    "pkg:github/run-llama/llama_index",
    "pkg:github/moyangzhan/langchain4j-aideepin",
    "pkg:github/stevereiner/flexible-graphrag",
    "pkg:maven/io.quarkiverse.langchain4j",
    "pkg:npm/%40langchain",
    "pkg:npm/%40flowiseai",
    "pkg:npm/%40portkey-ai",
}

# Description keywords — last-resort fallback only. Do NOT add generic terms
# like "ai", "ml", "webui", "scheduler" or a bare "autogen".
GENAI_DESC_KEYWORDS = [
    "langchain", "langflow", "llamaindex", "llama_index", "ollama",
    "vllm", "flowise", "open-webui", "open webui", "openwebui",
    "autogpt", "crewai", "gpt-sovits", "lollms", "mlflow",
    "large language model", "llm-powered", "generative ai",
    "prompt injection", "retrieval-augmented", "agentos",
    "agent framework", "llm framework", "llm inference",
    "llm serving", "rag framework", "rag application",
    "langchain-chatchat", "langchain4j", "langchaingo",
    "langgraph", "langsmith", "lightrag", "mem0",
    "flexible-graphrag", "kubeai", "portkey",
]

CVE_CHILD_TABLES = [
    "descriptions", "cveTags", "affected", "cvss_metrics", "ssvc_metrics",
    "weaknesses", "cve_references", "configuration_nodes", "cve_source_files",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def norm(s):
    if not s:
        return ""
    return re.sub(r"[^a-z0-9]", "", s.lower())


def cpe_vendor_product(criteria):
    """cpe:2.3:a:vendor:product:... -> (vendor_norm, product_norm) or (None,None)."""
    if not criteria:
        return None, None
    parts = criteria.split(":")
    if len(parts) < 5:
        return None, None
    return norm(parts[3]), norm(parts[4])


def purl_matches(purl):
    if not purl:
        return False
    pl = purl.lower()
    return any(sub in pl for sub in GENAI_PURL_SUBSTRINGS)


def desc_matches(text):
    """Return the first matching keyword, or None."""
    if not text:
        return None
    t = text.lower()
    for k in GENAI_DESC_KEYWORDS:
        if k in t:
            return k
    return None


# ---------------------------------------------------------------------------
# Evidence gathering
# ---------------------------------------------------------------------------

def gather(conn):
    cur = conn.cursor()
    ev = {}

    for (cve_id,) in cur.execute("SELECT id FROM cves"):
        ev[cve_id] = {"cpes": [], "purls": [], "affected": [], "desc": ""}

    for cve_id, criteria in cur.execute("""
        SELECT n.cve_id, m.criteria
        FROM configuration_nodes n
        JOIN cpe_matches m ON m.node_row_id = n.rowid
    """):
        if cve_id in ev:
            ev[cve_id]["cpes"].append(criteria or "")

    for cve_id, vendor, product, purl in cur.execute("""
        SELECT cve_id, vendor, product, packageURL FROM affected
    """):
        if cve_id in ev:
            ev[cve_id]["affected"].append((vendor, product))
            if purl:
                ev[cve_id]["purls"].append(purl)

    for cve_id, value in cur.execute(
        "SELECT cve_id, value FROM descriptions WHERE lang='en'"
    ):
        if cve_id in ev and not ev[cve_id]["desc"]:
            ev[cve_id]["desc"] = value or ""

    return ev


def decide(cve_id, e):
    # 0. explicit deny (highest priority)
    if cve_id in DENY_CVE_IDS:
        return "delete", f"denied: {DENY_CVE_IDS[cve_id]}"

    # 1. CPE vendor:product pair (very specific)
    for crit in e["cpes"]:
        vend, prod = cpe_vendor_product(crit)
        if vend and prod and (vend, prod) in KEEP_VENDOR_PRODUCT_PAIRS:
            return "keep", f"CPE pair {crit}"

    # 2. CPE product name
    for crit in e["cpes"]:
        _, prod = cpe_vendor_product(crit)
        if prod and prod in KEEP_PRODUCTS:
            return "keep", f"CPE {crit}"

    # 3. purl
    for purl in e["purls"]:
        if purl_matches(purl):
            return "keep", f"purl {purl}"

    # 4. affected vendor/product — pair first, then bare product
    for v, p in e["affected"]:
        nv, np_ = norm(v), norm(p)
        if nv and np_ and (nv, np_) in KEEP_VENDOR_PRODUCT_PAIRS:
            return "keep", f"affected {v}/{p} (pair)"
    for v, p in e["affected"]:
        if norm(p) in KEEP_PRODUCTS:
            return "keep", f"affected {v}/{p}"

    # 5. description (last resort) — report the keyword that matched
    kw = desc_matches(e["desc"])
    if kw:
        snippet = e["desc"][:90].replace("\n", " ")
        return "keep", f"desc [{kw}]: {snippet}..."
    return "delete", "no GenAI signal"


# ---------------------------------------------------------------------------
# Deletion
# ---------------------------------------------------------------------------

def delete_cves(cur, cve_ids):
    if not cve_ids:
        return {}
    ph = ",".join("?" * len(cve_ids))
    counts = {}

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

    for t in CVE_CHILD_TABLES:
        cur.execute(f"DELETE FROM {t} WHERE cve_id IN ({ph})", cve_ids)
        counts[t] = cur.rowcount

    cur.execute(f"DELETE FROM cves WHERE id IN ({ph})", cve_ids)
    counts["cves"] = cur.rowcount
    return counts


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--apply", action="store_true",
                    help="Actually delete (default: dry-run)")
    ap.add_argument("--list-keep", action="store_true",
                    help="Also print kept CVEs with reasons")
    ap.add_argument("--all-deleted", action="store_true",
                    help="Print every CVE that would be deleted (default: first 50)")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        sys.exit(f"DB not found: {args.db}")

    conn = sqlite3.connect(args.db)
    ev = gather(conn)

    keep, delete = [], []
    reasons = {}
    for cve_id in sorted(ev):
        action, reason = decide(cve_id, ev[cve_id])
        reasons[cve_id] = reason
        (keep if action == "keep" else delete).append(cve_id)

    print(f"Total CVEs          : {len(ev)}")
    print(f"Keep (GenAI signal) : {len(keep)}")
    print(f"Delete (no signal)  : {len(delete)}\n")

    if args.list_keep:
        print("=== KEEP ===")
        for c in keep:
            print(f"  {c}: {reasons[c]}")
        print()

    limit = len(delete) if args.all_deleted else 50
    if delete:
        print(f"=== DELETE (first {min(limit, len(delete))} of {len(delete)}) ===")
        for c in delete[:limit]:
            print(f"  {c}: {reasons[c]}")
        if limit < len(delete):
            print(f"  ... {len(delete) - limit} more (use --all-deleted)")
        print()

    if not args.apply:
        print("Dry-run — nothing deleted. Re-run with --apply to commit.")
        conn.close()
        return

    counts = delete_cves(conn.cursor(), delete)
    conn.commit()
    print("Deleted rows per table:")
    for t, n in counts.items():
        print(f"  {t:<24}{n}")
    conn.close()


if __name__ == "__main__":
    main()