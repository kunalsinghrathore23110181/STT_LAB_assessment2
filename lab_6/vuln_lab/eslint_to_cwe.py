import json
import csv
from collections import Counter
import matplotlib.pyplot as plt
import os

# Get the directory where the script is located
script_dir = os.path.dirname(os.path.abspath(__file__))

# Relative path to the ESLint JSON file inside BPB-Worker-Panel
json_path = os.path.join(script_dir, "BPB-Worker-Panel", "eslint_report.json")

# Load ESLint JSON report
with open(json_path, "r", encoding="utf-8") as f:
    data = json.load(f)

# CWE mapping dictionary
CWE_MAP = {
    "security/detect-eval-with-expression": "CWE-95",      # Code Injection
    "no-eval": "CWE-95",
    "no-implied-eval": "CWE-95",
    "security/detect-non-literal-require": "CWE-22",       # Path Traversal
    "security/detect-object-injection": "CWE-915",         # Object Injection
    "security/detect-child-process": "CWE-78",             # Command Injection
    "security/detect-new-buffer": "CWE-120",               # Buffer Handling
    "security/detect-buffer-noassert": "CWE-120",
    "security/detect-disable-mustache-escape": "CWE-79",   # XSS
    "security/detect-html-encoding": "CWE-79",
    "security/detect-unsafe-regex": "CWE-400",             # ReDoS
}

rows = []
cwe_counter = Counter()

# Parse ESLint results
for file_report in data:
    file_path = file_report.get("filePath", "")
    for msg in file_report.get("messages", []):
        rule = msg.get("ruleId", "N/A")
        message = msg.get("message", "")
        severity = "Error" if msg.get("severity") == 2 else "Warning"
        cwe = CWE_MAP.get(rule, "CWE-Other")

        rows.append([file_path, rule, cwe, severity, message])
        cwe_counter[cwe] += 1

# Save CSV report in the same folder as JSON
csv_path = os.path.join(os.path.dirname(json_path), "eslint_cwe_report.csv")
with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["File", "ESLint Rule", "Mapped CWE", "Severity", "Message"])
    writer.writerows(rows)

# Print summary
print(f"\n✅ Done! Report saved as {csv_path} ({len(rows)} findings)\n")
print("📊 CWE Summary:")
print("-" * 40)
for cwe, count in cwe_counter.most_common():
    print(f"{cwe:10s} : {count}")
print("-" * 40)

# ---------- Plot the Graph ----------
if cwe_counter:
    plt.figure(figsize=(10, 6))
    cwes = list(cwe_counter.keys())
    counts = list(cwe_counter.values())

    plt.bar(cwes, counts, color='skyblue')
    plt.xlabel("CWE Categories")
    plt.ylabel("Number of Findings")
    plt.title("CWE Vulnerability Distribution from ESLint Scan")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()

    graph_path = os.path.join(os.path.dirname(json_path), "eslint_cwe_graph.png")
    plt.savefig(graph_path, dpi=300)
    plt.close()
    print(f"📈 Graph generated: {graph_path}")
else:
    print("⚠️ No CWE findings to plot.")
