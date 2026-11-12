# Confidentiality, Integrity, or Availability? What 825 GenAI CVEs actually reveal

We analyzed **825 valid CVEs** with CVSS v3.1 scores across popular Generative AI tools (extracted from NVD on **November 10, 2026**).

## The Result

- **Confidentiality** — **75.6%** (624 cases) — the most impacted component
- **Integrity** — 63.3%
- **Availability** — 60.2%

## The Interesting Contrast: Between Tools

In agent and chatbot platforms, nearly 90% of bugs hit **Confidentiality** (e.g., API key theft):

- **Flowise** — 92.5%
- **LangChain** — 91.5%
- **Langflow** — 89.6%

But in model-serving engines, the story flips — **Availability** (service crashes) takes the biggest hit:

- **vLLM** — 85.9%
- **Ollama** — 66.7%

## ⚠️ Important

- These are **potential impacts** based on CVSS v3.1.
- Since a single CVE can affect all three dimensions simultaneously, **the percentages do not sum to 100%**.
- Despite an average severity of **7.45/10**, the EPSS score shows the real-world exploitation likelihood for most is **below 1%** (median **0.45%**).

## 🔍 Limitations

- Snapshot from **November 10, 2026** (NVD API 2.0).
- CVSS v3.1 reflects potential rather than actual damage.
- **34 CVEs** lacking v3.1 metrics were excluded.

## 💬 Question

What do you think? Should AI developers prioritize **data security** or **service stability**?

---

`#GenerativeAI` `#CyberSecurity` `#CVE` `#CVSS` `#AISecurity`