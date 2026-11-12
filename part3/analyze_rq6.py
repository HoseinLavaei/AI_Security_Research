import os
import sqlite3
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# پیدا کردن مسیر دقیق پوشه part1&2
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "nvd_cve.db")
CSV_OUT = os.path.join(BASE_DIR, "genai_cves_cvss31.csv")
PNG_OUT = os.path.join(BASE_DIR, "rq6_cia_stacked_bar.png")

conn = sqlite3.connect(DB_PATH)
df = pd.read_sql("SELECT * FROM cves_flat", conn)

# ذخیره CSV در پوشه part1&2
df.to_csv(CSV_OUT, index=False, encoding="utf-8-sig")
print("1. فایل ساخته شد در:", CSV_OUT)

valid = df[df["C"].notna()].copy()
main_groups = ["Langflow", "Open WebUI", "Flowise", "vLLM", "LangChain", "Ollama", "AutoGPT"]
t1 = valid[valid["group"].isin(main_groups)]

fig, axes = plt.subplots(1, 3, figsize=(15, 6), sharey=True)
metrics = [("C", "Confidentiality (C)"), ("I", "Integrity (I)"), ("A", "Availability (A)")]
colors = {"HIGH": "#d9534f", "LOW": "#f0ad4e", "NONE": "#cfd8dc"}

y_pos = np.arange(len(main_groups))
y_labels = [f"{g}\n(n={len(t1[t1['group'] == g])})" for g in main_groups][::-1]

for ax, (col, title) in zip(axes, metrics):
    highs, lows, nones = [], [], []
    for g in main_groups[::-1]:
        sub = t1[t1["group"] == g]
        n = len(sub)
        highs.append((sub[col] == "HIGH").sum() / n * 100)
        lows.append((sub[col] == "LOW").sum() / n * 100)
        nones.append((sub[col] == "NONE").sum() / n * 100)

    highs, lows, nones = np.array(highs), np.array(lows), np.array(nones)
    ax.barh(y_pos, highs, color=colors["HIGH"], edgecolor="white", height=0.65, label="High")
    ax.barh(y_pos, lows, left=highs, color=colors["LOW"], edgecolor="white", height=0.65, label="Low")
    ax.barh(y_pos, nones, left=highs + lows, color=colors["NONE"], edgecolor="white", height=0.65, label="None")

    for i in range(len(main_groups)):
        if highs[i] >= 8:
            ax.text(highs[i]/2, y_pos[i], f"{highs[i]:.1f}%", va="center", ha="center", color="white", fontweight="bold", fontsize=8.5)
        if lows[i] >= 8:
            ax.text(highs[i] + lows[i]/2, y_pos[i], f"{lows[i]:.1f}%", va="center", ha="center", color="#222", fontweight="bold", fontsize=8.5)
        if nones[i] >= 8:
            ax.text(highs[i] + lows[i] + nones[i]/2, y_pos[i], f"{nones[i]:.1f}%", va="center", ha="center", color="#333", fontsize=8.5)

    ax.set_title(title, fontweight="bold")
    ax.set_xlim(0, 100)
    ax.set_xlabel("Share (%)")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

axes[0].set_yticks(y_pos)
axes[0].set_yticklabels(y_labels, fontweight="bold")
handles, labels = axes[0].get_legend_handles_labels()
fig.legend(handles, labels, loc="upper center", ncol=3, frameon=False, bbox_to_anchor=(0.5, 0.98))
plt.tight_layout(rect=[0, 0, 1, 0.93])

# ذخیره نمودار در پوشه part1&2
plt.savefig(PNG_OUT, dpi=300)
print("2. نمودار ساخته شد در:", PNG_OUT)
conn.close()