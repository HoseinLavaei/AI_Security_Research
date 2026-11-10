#!/usr/bin/env python3
"""
Build the `products` table — step 1 of the assignment.

Creates a small, hand-curated registry of every GenAI/LLM product present
in the corpus, with:
  - product / group / creator
  - official repository
  - aliases (sub-packages, alternative names, repo slugs)
  - CPE / purl hints for downstream joins against cpe_matches & affected
  - source JSON file (provenance, matches cve_source_files)
  - tier: 1 = the seven named tools, 2 = other GenAI tools, 3 = ecosystem

Idempotent: INSERT OR REPLACE; pass --drop to recreate from scratch.

Usage:
    python build_products.py            # create / refresh
    python build_products.py --show     # print current contents, no writes
    python build_products.py --drop     # drop table first, then rebuild
"""

import argparse
import json
import os
import re
import sqlite3
import sys

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nvd_cve.db")


# ---------------------------------------------------------------------------
# Seed data — one dict per product / project.
# ---------------------------------------------------------------------------

PRODUCTS = [
    # ============================ TIER 1 — named tools ============================
    {
        "product": "AutoGPT",
        "group_name": "AutoGPT",
        "creator": "Significant Gravitas",
        "official_repo": "https://github.com/Significant-Gravitas/AutoGPT",
        "aliases": [
            "AutoGPT", "Auto-GPT", "AutoGPT classic", "AutoGPT platform",
            "agpt", "autogpt_classic", "autogpt_platform",
            "Significant-Gravitas/AutoGPT", "Thesamur/AutoGPT",
        ],
        "cpe_vendors": ["agpt"],
        "cpe_products": ["autogpt_classic", "autogpt_platform"],
        "purl_substrings": ["pkg:github/significant-gravitas/autogpt"],
        "source_file": "AutoGPT_cve_data.json",
        "tier": 1,
    },
    {
        "product": "LangChain",
        "group_name": "LangChain",
        "creator": "LangChain, Inc.",
        "official_repo": "https://github.com/langchain-ai/langchain",
        "aliases": [
            "LangChain", "langchain-core", "langchain-community",
            "langchain-experimental", "langchain.js", "langchainjs",
            "langchain-text-splitters", "langchain-openai",
            "langchain-mongodb",
            "LangSmith", "langsmith", "langsmith-sdk",
            "LangGraph", "langgraph",
            "langgraph-checkpoint-mongodb", "langgraph-store-mongodb",
        ],
        "cpe_vendors": ["langchain"],
        "cpe_products": [
            "langchain", "langchain_experimental", "langchain_core",
            "langchain_community", "langchain.js",
            "langchain-text-splitters", "langchain-openai", "langsmith",
        ],
        "purl_substrings": [
            "pkg:pypi/langchain", "pkg:npm/langchain",
            "pkg:pypi/langsmith", "pkg:npm/langsmith",
            "pkg:pypi/langgraph", "pkg:npm/langgraph",
            "pkg:github/langchain-ai/langchain",
            "pkg:github/langchain-ai/langchainjs",
            "pkg:github/langchain-ai/langgraph",
            "pkg:github/langchain-ai/langsmith-sdk",
            "pkg:github/langchain-ai/langchain-mongodb",
            "pkg:npm/%40langchain",
        ],
        "source_file": "LangChain_cve_data.json",
        "tier": 1,
    },
    {
        "product": "Ollama",
        "group_name": "Ollama",
        "creator": "Ollama",
        "official_repo": "https://github.com/ollama/ollama",
        "aliases": ["Ollama", "ollama-mcp", "Ollama-mcp", "nuxt-ollama"],
        "cpe_vendors": ["ollama"],
        "cpe_products": ["ollama"],
        "purl_substrings": [
            "pkg:golang/github.com/ollama/ollama",
            "pkg:pypi/ollama",
        ],
        "source_file": "Ollama_cve_data.json",
        "tier": 1,
    },
    {
        "product": "vLLM",
        "group_name": "vLLM",
        "creator": "vLLM Project",
        "official_repo": "https://github.com/vllm-project/vllm",
        "aliases": [
            "vLLM", "vllm-metal", "vllm-hardware", "vllm-orchestrator-gateway",
        ],
        "cpe_vendors": ["vllm", "vllm-project", "intel"],
        "cpe_products": ["vllm", "vllm_hardware"],
        "purl_substrings": [
            "pkg:pypi/vllm", "pkg:github/vllm-project",
        ],
        "source_file": "vLLM_cve_data.json",
        "tier": 1,
    },
    {
        "product": "Open WebUI",
        "group_name": "Open WebUI",
        "creator": "Open WebUI",
        "official_repo": "https://github.com/open-webui/open-webui",
        "aliases": ["Open WebUI", "open-webui", "openwebui", "open_webui"],
        "cpe_vendors": ["openwebui"],
        "cpe_products": ["open_webui"],
        "purl_substrings": [
            "pkg:pypi/open-webui", "pkg:pypi/open_webui",
            "pkg:github/open-webui",
        ],
        "source_file": "Open_WebUI_cve_data.json",
        "tier": 1,
    },
    {
        "product": "Flowise",
        "group_name": "Flowise",
        "creator": "FlowiseAI",
        "official_repo": "https://github.com/FlowiseAI/Flowise",
        "aliases": [
            "Flowise", "flowise-components", "flowise-embed", "embed",
        ],
        "cpe_vendors": ["flowiseai"],
        "cpe_products": ["flowise", "embed"],
        "purl_substrings": [
            "pkg:npm/flowise", "pkg:npm/flowise-components",
            "pkg:pypi/flowise", "pkg:github/flowiseai",
        ],
        "source_file": "Flowise_cve_data.json",
        "tier": 1,
    },
    {
        "product": "Langflow",
        "group_name": "Langflow",
        "creator": "Langflow AI / IBM",
        "official_repo": "https://github.com/langflow-ai/langflow",
        "aliases": [
            "Langflow", "langflow-desktop", "langflow-base", "Langflow OSS",
        ],
        "cpe_vendors": ["langflow"],
        "cpe_products": ["langflow", "langflow_desktop", "langflow_base"],
        "purl_substrings": [
            "pkg:pypi/langflow", "pkg:github/langflow-ai",
        ],
        "source_file": "Langflow_cve_data.json",
        "tier": 1,
    },

    # ============================ TIER 2 — other GenAI tools ============================
    {
        "product": "LlamaIndex",
        "group_name": "LlamaIndex",
        "creator": "LlamaIndex",
        "official_repo": "https://github.com/run-llama/llama_index",
        "aliases": ["LlamaIndex", "llama_index", "llama-index"],
        "cpe_vendors": ["llamaindex"],
        "cpe_products": ["llamaindex"],
        "purl_substrings": [
            "pkg:pypi/llama_index", "pkg:pypi/llamaindex",
            "pkg:github/run-llama/llama_index",
        ],
        "source_file": "LlamaIndex_cve_data.json",
        "tier": 2,
    },
    {
        "product": "CrewAI",
        "group_name": "CrewAI",
        "creator": "CrewAI",
        "official_repo": "https://github.com/crewAIInc/crewAI",
        "aliases": ["CrewAI", "crewai-tools"],
        "cpe_vendors": ["crewai"],
        "cpe_products": ["crewai"],
        "purl_substrings": ["pkg:pypi/crewai", "pkg:pypi/crewai-tools"],
        "source_file": "CrewAI_cve_data.json",
        "tier": 2,
    },
    {
        "product": "AutoGen",
        "group_name": "AutoGen / AG2",
        "creator": "Microsoft (AutoGen) / ag2ai (AG2)",
        "official_repo": "https://github.com/ag2ai/ag2",
        "aliases": ["AutoGen", "AG2", "ag2", "pyautogen"],
        "cpe_vendors": ["ag2ai", "microsoft"],
        "cpe_products": ["ag2", "autogen"],
        "purl_substrings": [
            "pkg:pypi/ag2", "pkg:pypi/autogen", "pkg:pypi/pyautogen",
        ],
        "source_file": "AutoGen_cve_data.json",
        "tier": 2,
    },
    {
        "product": "LangChain-ChatChat",
        "group_name": "LangChain-ChatChat",
        "creator": "chatchat-space",
        "official_repo": "https://github.com/chatchat-space/Langchain-Chatchat",
        "aliases": [
            "LangChain-ChatChat", "langchain-chatchat",
            "langchain-chatglm-webui",
        ],
        "cpe_vendors": ["chatchat-space", "x-d_lab"],
        "cpe_products": ["langchain-chatchat", "langchain-chatglm-webui"],
        "purl_substrings": [
            "pkg:pypi/langchain-chatchat",
            "pkg:github/chatchat-space",
        ],
        "source_file": None,
        "tier": 2,
    },
    {
        "product": "LangChain4j",
        "group_name": "LangChain4j",
        "creator": "LangChain4j",
        "official_repo": "https://github.com/langchain4j/langchain4j",
        "aliases": ["LangChain4j", "langchain4j-aideepin"],
        "cpe_vendors": ["langchain4j", "moyangzhan"],
        "cpe_products": ["langchain4j", "langchain4j-aideepin"],
        "purl_substrings": [
            "pkg:maven/io.quarkiverse.langchain4j",
            "pkg:github/moyangzhan/langchain4j-aideepin",
        ],
        "source_file": None,
        "tier": 2,
    },

    # ============================ TIER 3 — ecosystem ============================
    {
        "product": "LightRAG",
        "group_name": "LightRAG",
        "creator": "HKUDS",
        "official_repo": "https://github.com/HKUDS/LightRAG",
        "aliases": ["LightRAG"],
        "cpe_vendors": [],
        "cpe_products": ["lightrag"],
        "purl_substrings": ["pkg:pypi/lightrag"],
        "source_file": None,
        "tier": 3,
    },
    {
        "product": "mem0",
        "group_name": "mem0",
        "creator": "mem0ai",
        "official_repo": "https://github.com/mem0ai/mem0",
        "aliases": ["mem0", "mem0ai"],
        "cpe_vendors": [],
        "cpe_products": ["mem0"],
        "purl_substrings": ["pkg:pypi/mem0ai"],
        "source_file": None,
        "tier": 3,
    },
    {
        "product": "Portkey Gateway",
        "group_name": "Portkey",
        "creator": "Portkey AI",
        "official_repo": "https://github.com/Portkey-AI/gateway",
        "aliases": ["Portkey", "portkey-ai", "portkey-gateway"],
        "cpe_vendors": [],
        "cpe_products": ["portkeyai", "portkeyaigateway"],
        "purl_substrings": ["pkg:npm/%40portkey-ai"],
        "source_file": None,
        "tier": 3,
    },
    {
        "product": "MLflow",
        "group_name": "MLflow",
        "creator": "Databricks / LF AI & Data",
        "official_repo": "https://github.com/mlflow/mlflow",
        "aliases": ["MLflow", "mlflow"],
        "cpe_vendors": ["lfprojects"],
        "cpe_products": ["mlflow"],
        "purl_substrings": ["pkg:pypi/mlflow"],
        "source_file": None,
        "tier": 3,
    },
    {
        "product": "Flexible-GraphRAG",
        "group_name": "Flexible-GraphRAG",
        "creator": "stevereiner",
        "official_repo": "https://github.com/stevereiner/flexible-graphrag",
        "aliases": ["flexible-graphrag"],
        "cpe_vendors": [],
        "cpe_products": ["flexiblegraphrag"],
        "purl_substrings": ["pkg:github/stevereiner/flexible-graphrag"],
        "source_file": None,
        "tier": 3,
    },
    {
        "product": "KubeAI",
        "group_name": "KubeAI",
        "creator": "substratusai",
        "official_repo": "https://github.com/substratusai/kubeai",
        "aliases": ["kubeai"],
        "cpe_vendors": ["kubeai"],
        "cpe_products": ["kubeai"],
        "purl_substrings": [],
        "source_file": None,
        "tier": 3,
    },
    {
        "product": "GPT-SoVITS",
        "group_name": "GPT-SoVITS",
        "creator": "RVC-Boss",
        "official_repo": "https://github.com/RVC-Boss/GPT-SoVITS",
        "aliases": ["GPT-SoVITS", "gpt-sovits-webui"],
        "cpe_vendors": ["rvc-boss"],
        "cpe_products": ["gpt-sovits-webui"],
        "purl_substrings": [],
        "source_file": None,
        "tier": 3,
    },
    {
        "product": "LoLLMs",
        "group_name": "LoLLMs",
        "creator": "ParisNeo",
        "official_repo": "https://github.com/ParisNeo/lollms-webui",
        "aliases": ["LoLLMs", "lollms-webui"],
        "cpe_vendors": ["lollms"],
        "cpe_products": ["lollms-webui"],
        "purl_substrings": [],
        "source_file": None,
        "tier": 3,
    },
]


# ---------------------------------------------------------------------------
# Schema + helpers
# ---------------------------------------------------------------------------

def norm(s):
    if not s:
        return ""
    return re.sub(r"[^a-z0-9]", "", s.lower())


CREATE_SQL = """
CREATE TABLE IF NOT EXISTS products (
    product          TEXT PRIMARY KEY,
    product_norm     TEXT NOT NULL UNIQUE,
    group_name       TEXT NOT NULL,
    creator          TEXT,
    official_repo    TEXT,
    aliases          TEXT,       -- JSON array of alias strings
    aliases_norm     TEXT,       -- JSON array of normalized aliases
    cpe_vendors      TEXT,       -- JSON array of normalized vendor names
    cpe_products     TEXT,       -- JSON array of normalized product names
    purl_substrings  TEXT,       -- JSON array of purl substrings (case-sensitive as stored)
    source_file      TEXT,
    tier             INTEGER NOT NULL,
    notes            TEXT
);
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_products_group ON products(group_name);",
    "CREATE INDEX IF NOT EXISTS idx_products_tier  ON products(tier);",
    "CREATE INDEX IF NOT EXISTS idx_products_src   ON products(source_file);",
]

INSERT_SQL = """
INSERT OR REPLACE INTO products
    (product, product_norm, group_name, creator, official_repo,
     aliases, aliases_norm, cpe_vendors, cpe_products, purl_substrings,
     source_file, tier, notes)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
"""


def jlist(xs, normalize=True):
    """JSON-encode a list; optionally normalize each entry (lowercase alnum)."""
    if not xs:
        return "[]"
    if normalize:
        cleaned = sorted({norm(x) for x in xs if x})
    else:
        cleaned = list(xs)
    return json.dumps(cleaned, ensure_ascii=False)


def build(conn, drop_first=False):
    cur = conn.cursor()
    if drop_first:
        cur.execute("DROP TABLE IF EXISTS products")
        print("dropped existing products table")

    cur.execute(CREATE_SQL)
    for stmt in CREATE_INDEXES:
        cur.execute(stmt)

    n = 0
    for p in PRODUCTS:
        cur.execute(INSERT_SQL, (
            p["product"],
            norm(p["product"]),
            p["group_name"],
            p.get("creator"),
            p.get("official_repo"),
            jlist(p.get("aliases") or [], normalize=False),
            jlist(p.get("aliases") or [], normalize=True),
            jlist(p.get("cpe_vendors") or [], normalize=True),
            jlist(p.get("cpe_products") or [], normalize=True),
            jlist(p.get("purl_substrings") or [], normalize=False),
            p.get("source_file"),
            p["tier"],
            p.get("notes"),
        ))
        n += 1

    conn.commit()
    print(f"inserted/updated {n} rows")


def show(conn):
    cur = conn.cursor()
    rows = cur.execute("""
        SELECT product, group_name, creator, official_repo, tier, source_file
        FROM products
        ORDER BY tier, product
    """).fetchall()
    if not rows:
        print("(empty)")
        return

    print(f"{'tier':<5}{'product':<22}{'group':<22}{'creator':<28}{'source_file'}")
    print("-" * 110)
    for r in rows:
        product, group, creator, repo, tier, src = r
        print(f"{tier:<5}{product:<22}{group:<22}{(creator or '-'):<28}{src or '-'}")
        print(f"     repo: {repo or '-'}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--drop", action="store_true", help="Drop table then recreate")
    ap.add_argument("--show", action="store_true", help="Print current products table and exit")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        sys.exit(f"DB not found: {args.db}")

    conn = sqlite3.connect(args.db)
    try:
        if args.show:
            show(conn)
            return

        build(conn, drop_first=args.drop)
        print()
        show(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()