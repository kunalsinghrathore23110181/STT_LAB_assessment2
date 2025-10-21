import os
import json
import pandas as pd
import itertools
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from tabulate import tabulate  # ✅ for nicely formatted console tables

# -------------------------------
# Step 1: Configuration
# -------------------------------

REPORTS_DIR = "/home/set-iitgn-vm/Desktop/Stt_lab2/vuln_lab"

CWE_TOP_25 = {
    "CWE-787","CWE-79","CWE-89","CWE-20","CWE-125","CWE-78","CWE-416",
    "CWE-22","CWE-352","CWE-434","CWE-862","CWE-476","CWE-306","CWE-190",
    "CWE-502","CWE-287","CWE-77","CWE-119","CWE-798","CWE-918","CWE-362",
    "CWE-94","CWE-863","CWE-276","CWE-269"
}

tool_files = [
    "bandit_report_repo1.json",
    "bandit_report_repo2.json",
    "eslint_cwe_report.csv",
    "eslint_report.json",
    "safety_report.json",
    "semgrep_agentzero.json",
    "semgrep_bpbworker.json",
    "semgrep_chattts.json"
]
tool_files = [os.path.join(REPORTS_DIR, f) for f in tool_files]

print(f"✅ Found {len(tool_files)} files for analysis.\n")

# -------------------------------
# Step 2: Parse and Normalize Data
# -------------------------------

records = []

for file_path in tool_files:
    filename = os.path.basename(file_path)
    parts = filename.split("_")
    tool = parts[0].capitalize() if len(parts) > 1 else "UnknownTool"
    project_name = parts[1].split(".")[0] if len(parts) > 1 else "UnknownProject"

    print(f"📄 Processing {filename} (Tool: {tool}, Project: {project_name})")

    if file_path.endswith(".json"):
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except Exception as e:
                print(f"⚠️ Could not read {filename}: {e}")
                continue
        for item in data:
            if isinstance(item, dict):
                cwe = item.get("CWE_ID") or item.get("cwe") or item.get("cwe_id")
                if cwe:
                    records.append((project_name, tool, str(cwe).strip()))
    elif file_path.endswith(".csv"):
        try:
            df = pd.read_csv(file_path)
        except Exception as e:
            print(f"⚠️ Could not read {filename}: {e}")
            continue
        cwe_col = [c for c in df.columns if "CWE" in c.upper()]
        if cwe_col:
            for cwe in df[cwe_col[0]].dropna():
                records.append((project_name, tool, str(cwe).strip()))

# -------------------------------
# Step 3: Aggregate Findings
# -------------------------------

df = pd.DataFrame(records, columns=["Project_name", "Tool_name", "CWE_ID"])
agg_df = df.groupby(["Project_name", "Tool_name", "CWE_ID"]).size().reset_index(name="Number_of_Findings")
agg_df["Is_In_CWE_Top_25?"] = agg_df["CWE_ID"].apply(lambda x: "Yes" if x in CWE_TOP_25 else "No")

agg_df_path = os.path.join(REPORTS_DIR, "consolidated_findings.csv")
agg_df.to_csv(agg_df_path, index=False)
print("\n✅ Saved consolidated findings to 'consolidated_findings.csv'")

# Display table preview (all rows, formatted)
print("\n📋 Consolidated Findings:\n")
print(tabulate(agg_df, headers='keys', tablefmt='grid', showindex=False))

# -------------------------------
# Step 4: Tool-level CWE Coverage
# -------------------------------

tool_coverage = (
    agg_df.groupby("Tool_name")["CWE_ID"]
    .unique()
    .reset_index(name="Unique_CWEs")
)
tool_coverage["Total_CWEs"] = tool_coverage["Unique_CWEs"].apply(len)
tool_coverage["CWE_Top_25_Found"] = tool_coverage["Unique_CWEs"].apply(lambda cwes: len(set(cwes) & CWE_TOP_25))
tool_coverage["Coverage_%"] = (tool_coverage["CWE_Top_25_Found"] / len(CWE_TOP_25)) * 100

tool_coverage_path = os.path.join(REPORTS_DIR, "tool_coverage_summary.csv")
tool_coverage.to_csv(tool_coverage_path, index=False)
print("\n✅ Saved tool coverage summary to 'tool_coverage_summary.csv'")

print("\n📊 Tool Coverage Summary:\n")
print(tabulate(tool_coverage[["Tool_name", "Total_CWEs", "CWE_Top_25_Found", "Coverage_%"]],
               headers='keys', tablefmt='grid', showindex=False))

# -------------------------------
# Step 5: Pairwise IoU (Jaccard Index)
# -------------------------------

tools = tool_coverage["Tool_name"].tolist()
iou_matrix = pd.DataFrame(index=tools, columns=tools)

for t1, t2 in itertools.product(tools, tools):
    cwe1 = set(tool_coverage.loc[tool_coverage["Tool_name"]==t1, "Unique_CWEs"].values[0])
    cwe2 = set(tool_coverage.loc[tool_coverage["Tool_name"]==t2, "Unique_CWEs"].values[0])
    intersection = len(cwe1 & cwe2)
    union = len(cwe1 | cwe2)
    iou = intersection / union if union != 0 else 0
    iou_matrix.loc[t1, t2] = round(iou, 3)

iou_path = os.path.join(REPORTS_DIR, "tool_iou_matrix.csv")
iou_matrix.to_csv(iou_path)
print("\n✅ Saved IoU matrix to 'tool_iou_matrix.csv'")

# Display IoU table (all rows, formatted)
print("\n📋 Pairwise IoU Matrix:\n")
print(tabulate(iou_matrix, headers='keys', tablefmt='grid', showindex=True))

# -------------------------------
# Step 6: Per-Project Analysis + Heatmaps
# -------------------------------

project_summary = []
project_names = df["Project_name"].unique()

for project in project_names:
    project_df = agg_df[agg_df["Project_name"] == project]
    tools_in_project = project_df["Tool_name"].unique().tolist()
    if len(tools_in_project) == 0:
        continue  # Skip projects with no tools

    project_matrix = pd.DataFrame(index=tools_in_project, columns=tools_in_project)
    for t1, t2 in itertools.product(tools_in_project, tools_in_project):
        cwe1 = set(project_df.loc[project_df["Tool_name"] == t1, "CWE_ID"])
        cwe2 = set(project_df.loc[project_df["Tool_name"] == t2, "CWE_ID"])
        intersection = len(cwe1 & cwe2)
        union = len(cwe1 | cwe2)
        iou = intersection / union if union != 0 else 0
        project_matrix.loc[t1, t2] = round(iou, 3)

    plt.figure(figsize=(6, 5))
    sns.heatmap(project_matrix.astype(float), annot=True, cmap="YlGnBu", fmt=".2f")
    plt.title(f"IoU Heatmap for Project: {project}")
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, f"{project}_iou_heatmap.png"))
    plt.close()

    unique_cwes = len(project_df["CWE_ID"].unique())
    top25_covered = len(set(project_df["CWE_ID"]) & CWE_TOP_25)
    coverage_pct = (top25_covered / len(CWE_TOP_25)) * 100
    project_summary.append((project, unique_cwes, top25_covered, coverage_pct))

project_summary_df = pd.DataFrame(project_summary, columns=["Project", "Unique_CWEs", "Top25_CWEs_Found", "Coverage_%"])
project_summary_df.to_csv(os.path.join(REPORTS_DIR, "project_wise_summary.csv"), index=False)
print("\n✅ Saved per-project summary to 'project_wise_summary.csv'")

# -------------------------------
# Step 7: Insights
# -------------------------------

if not tool_coverage.empty:
    max_tool = tool_coverage.loc[tool_coverage["Coverage_%"].idxmax()]
    print(f"\n🏆 Tool with Maximum CWE Coverage: {max_tool['Tool_name']} ({max_tool['Coverage_%']:.2f}%)")

if not iou_matrix.empty:
    # Only consider off-diagonal entries for "most similar tools"
    off_diagonal = iou_matrix.where(~np.eye(len(iou_matrix), dtype=bool))

    if off_diagonal.notna().any().any():
        max_iou_val = off_diagonal.stack().astype(float).max()
        if max_iou_val == 0:
            print("🤝 No overlapping CWEs between different tools (Highest IoU = 0)")
        else:
            max_iou_pair = off_diagonal.stack().idxmax()
            print(f"🤝 Most Similar Tools (Highest IoU): {max_iou_pair} = {max_iou_val:.3f}")
    else:
        print("🤝 Not enough tools to compute similarity (IoU).")

combined_cwes = set().union(*tool_coverage["Unique_CWEs"])
combined_top25 = len(combined_cwes & CWE_TOP_25)
print(f"\n🧩 Combined Tools Top-25 CWE Coverage: {combined_top25}/{len(CWE_TOP_25)} = {(combined_top25/len(CWE_TOP_25))*100:.1f}%")

# -------------------------------
# Step 8: Graphs for Report
# -------------------------------

# Graph 1: Tool Total CWE Findings
plt.figure(figsize=(8,5))
sns.barplot(x='Tool_name', y='Total_CWEs', data=tool_coverage)
plt.title('Total CWE Findings per Tool')
plt.ylabel('Number of Unique CWEs')
plt.xlabel('Tool')
plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, "tool_total_cwe_bar.png"))
plt.close()

# Graph 2: Tool Top-25 CWE Coverage
plt.figure(figsize=(8,5))
sns.barplot(x='Tool_name', y='CWE_Top_25_Found', data=tool_coverage)
plt.title('Top-25 CWE Coverage per Tool')
plt.ylabel('Number of Top-25 CWEs Found')
plt.xlabel('Tool')
plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, "tool_top25_cwe_bar.png"))
plt.close()

# Graph 3: Per-Project Top-25 CWE Coverage (%)
plt.figure(figsize=(10,5))
sns.barplot(x='Project', y='Coverage_%', data=project_summary_df)
plt.title('Per-Project Top-25 CWE Coverage (%)')
plt.ylabel('Coverage (%)')
plt.xlabel('Project')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, "project_coverage_bar.png"))
plt.close()

print("\n📈 Analysis Complete! All CSVs, tables, and graphs saved in:", REPORTS_DIR)
