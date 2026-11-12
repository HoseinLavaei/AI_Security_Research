# Is the biggest risk in Generative AI "getting hacked" or "going down"? Our findings are surprising! 🚨

We analyzed 825 valid CVEs with CVSS v3.1 scores across popular Generative AI tools (extracted from NVD on November 10, 2026). The result? **Confidentiality** is the most impacted component at **75.6% (624 cases)**, followed by **Integrity (63.3%)** and **Availability (60.2%)**.

The interesting contrast lies between tools: in agent and chatbot platforms like **Flowise (92.5%)**, **LangChain (91.5%)**, and **Langflow (89.6%)**, nearly **90%** of bugs hit **Confidentiality** (e.g., API key theft). But in model-serving engines like **vLLM (85.9%)** and **Ollama (66.7%)**, the story flips—**Availability** (service crashes) takes the biggest hit.

⚠️ **Important:** These are potential impacts based on CVSS v3.1. Since a single CVE can affect all three dimensions simultaneously, the percentages do not sum to 100%. Also, despite an average severity of **7.45/10**, the EPSS score shows the real-world exploitation likelihood for most is **below 1%** (median **0.45%**).

🔍 **Limitations:** Snapshot from **Nov 10, 2026** (NVD API 2.0); CVSS v3.1 reflects potential rather than actual damage, and **34 CVEs** lacking v3.1 metrics were excluded.

💬 What do you think? Should AI developers prioritize **data security** or **service stability**?

#GenerativeAI #CyberSecurity #CVE #CVSS #AISecurity