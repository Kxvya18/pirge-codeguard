from __future__ import annotations

import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap, BoundaryNorm


OUT = Path("figures/advanced")
OUT.mkdir(parents=True, exist_ok=True)


def load_csv(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n) / denom
    return max(0, center - margin), min(1, center + margin)


def savefig(name: str):
    plt.tight_layout()
    plt.savefig(OUT / name, dpi=220)
    plt.close()


def plot_accuracy_with_ci(rows: list[dict]):
    methods = ["pirge_codeguard", "keyword_filter", "sandbox_only", "no_guard"]
    labels = ["PIRGE-CodeGuard", "Keyword\nFilter", "Sandbox\nOnly", "No Guard"]
    colors = ["#1B7F5A", "#D99A00", "#536878", "#B73535"]
    values = []
    yerr_low = []
    yerr_high = []
    for method in methods:
        correct = sum(1 for r in rows if r[method] == r["expected"])
        n = len(rows)
        p = correct / n
        lo, hi = wilson(correct, n)
        values.append(p)
        yerr_low.append(p - lo)
        yerr_high.append(hi - p)

    plt.figure(figsize=(9.5, 5.2))
    x = range(len(methods))
    plt.bar(x, values, color=colors, edgecolor="#222", linewidth=0.7)
    plt.errorbar(x, values, yerr=[yerr_low, yerr_high], fmt="none", ecolor="#222", capsize=5, lw=1.2)
    plt.xticks(x, labels)
    plt.ylim(0, 1.08)
    plt.ylabel("Decision accuracy with Wilson 95% CI")
    plt.title("Controlled Evaluation: Accuracy Is High But Sample Size Is Small")
    for i, v in enumerate(values):
        plt.text(i, v + 0.035, f"{v:.0%}", ha="center", fontsize=10)
    plt.figtext(0.5, 0.01, "Intervals are wide because the controlled suite has 23 actions; this is a mechanism check, not production proof.", ha="center", fontsize=9)
    savefig("accuracy_with_confidence_intervals.png")


def plot_confusion_matrices(rows: list[dict]):
    methods = ["pirge_codeguard", "keyword_filter", "sandbox_only", "no_guard"]
    labels = ["PIRGE-CodeGuard", "Keyword Filter", "Sandbox Only", "No Guard"]
    fig, axes = plt.subplots(1, 4, figsize=(13, 3.8))
    for ax, method, label in zip(axes, methods, labels):
        tp = sum(1 for r in rows if r["expected"] == "block" and r[method] == "block")
        fn = sum(1 for r in rows if r["expected"] == "block" and r[method] == "allow")
        fp = sum(1 for r in rows if r["expected"] == "allow" and r[method] == "block")
        tn = sum(1 for r in rows if r["expected"] == "allow" and r[method] == "allow")
        matrix = [[tp, fn], [fp, tn]]
        ax.imshow(matrix, cmap="YlGnBu", vmin=0, vmax=max(1, max(map(max, matrix))))
        ax.set_title(label, fontsize=10)
        ax.set_xticks([0, 1], ["Pred Block", "Pred Allow"], rotation=30, ha="right")
        ax.set_yticks([0, 1], ["Actual Attack", "Actual Benign"])
        for i in range(2):
            for j in range(2):
                ax.text(j, i, str(matrix[i][j]), ha="center", va="center", fontsize=12, fontweight="bold")
    fig.suptitle("Confusion Matrices: Security Failures Are False Allows", y=1.03)
    savefig("confusion_matrices.png")


def plot_attack_category_baseline_gap(rows: list[dict]):
    attack_rows = [r for r in rows if r["expected"] == "block"]
    categories = []
    for r in attack_rows:
        risks = [x for x in r["risk_tags"].split(",") if x]
        caps = [x for x in r["capabilities"].split(",") if x]
        categories.append((r, risks[0] if risks else (caps[0] if caps else "intent_only")))
    cat_names = sorted(set(c for _, c in categories))
    methods = ["pirge_codeguard", "keyword_filter", "sandbox_only"]
    labels = ["PIRGE", "Keyword", "Sandbox"]
    colors = ["#1B7F5A", "#D99A00", "#536878"]

    fig, ax = plt.subplots(figsize=(11, 5.5))
    width = 0.24
    x = list(range(len(cat_names)))
    for idx, method in enumerate(methods):
        vals = []
        for cat in cat_names:
            subset = [r for r, c in categories if c == cat]
            vals.append(sum(1 for r in subset if r[method] == "block") / len(subset))
        ax.bar([i + (idx - 1) * width for i in x], vals, width=width, label=labels[idx], color=colors[idx])
    ax.set_xticks(x, cat_names, rotation=25, ha="right")
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Attack block rate")
    ax.set_title("Attack Blocking by Risk/Capability Category")
    ax.legend()
    savefig("attack_category_block_rates.png")


def short_scenario(name: str) -> str:
    return name.replace("S", "S").replace("_", " ")


def plot_method_decision_heatmap(rows: list[dict]):
    methods = ["pirge_codeguard", "keyword_filter", "sandbox_only", "no_guard"]
    labels = ["PIRGE", "Keyword", "Sandbox", "No Guard"]
    ylabels = [f"{r['scenario_id'].split('_')[0]}:{r['action_id']}" for r in rows]
    matrix = []
    for r in rows:
        line = []
        for m in methods:
            if r[m] == r["expected"]:
                line.append(1)
            elif r["expected"] == "block" and r[m] == "allow":
                line.append(-1)
            else:
                line.append(0)
        matrix.append(line)

    cmap = ListedColormap(["#B73535", "#D9D9D9", "#1B7F5A"])
    norm = BoundaryNorm([-1.5, -0.5, 0.5, 1.5], cmap.N)
    fig, ax = plt.subplots(figsize=(8.5, max(6, len(rows) * 0.31)))
    ax.imshow(matrix, cmap=cmap, norm=norm, aspect="auto")
    ax.set_xticks(range(len(methods)), labels)
    ax.set_yticks(range(len(rows)), ylabels, fontsize=7)
    ax.set_title("Per-Action Decision Matrix\nGreen=correct, Red=false allow/security miss, Gray=false block")
    for i, r in enumerate(rows):
        for j, m in enumerate(methods):
            mark = "✓" if matrix[i][j] == 1 else ("FA" if matrix[i][j] == -1 else "FB")
            ax.text(j, i, mark, ha="center", va="center", fontsize=7, color="white" if matrix[i][j] != 0 else "#111")
    savefig("per_action_decision_matrix.png")


def plot_false_allow_map(rows: list[dict]):
    attacks = [r for r in rows if r["expected"] == "block"]
    methods = ["pirge_codeguard", "keyword_filter", "sandbox_only", "no_guard"]
    labels = ["PIRGE", "Keyword", "Sandbox", "No Guard"]
    ylabels = []
    matrix = []
    for r in attacks:
        risk = r["risk_tags"] or r["capabilities"] or "intent"
        ylabels.append(f"{r['scenario_id'].split('_')[0]}:{r['action_id']}\n{risk[:32]}")
        matrix.append([1 if r[m] == "allow" else 0 for m in methods])
    fig, ax = plt.subplots(figsize=(8.5, max(5, len(attacks) * 0.48)))
    ax.imshow(matrix, cmap=ListedColormap(["#F2F2F2", "#B73535"]), aspect="auto", vmin=0, vmax=1)
    ax.set_xticks(range(len(methods)), labels)
    ax.set_yticks(range(len(attacks)), ylabels, fontsize=7)
    ax.set_title("False-Allow Map: Which Attacks Each Method Misses")
    for i in range(len(attacks)):
        for j in range(len(methods)):
            ax.text(j, i, "MISS" if matrix[i][j] else "BLOCK", ha="center", va="center", fontsize=7, color="white" if matrix[i][j] else "#333")
    savefig("false_allow_attack_map.png")


def plot_reason_capability_matrix(trace_rows: list[dict]):
    blocked = [r for r in trace_rows if r["decision"] == "block"]
    reason_counter = Counter()
    cap_counter = Counter()
    pairs = Counter()
    for r in blocked:
        caps = [c for c in r["capabilities"].split(",") if c]
        reasons = [x.split(":")[0] for x in r["reasons"].split(" | ") if x]
        for c in caps:
            cap_counter[c] += 1
        for reason in reasons:
            reason_counter[reason] += 1
        for reason in reasons:
            for cap in caps:
                pairs[(reason, cap)] += 1
    reasons = [k for k, _ in reason_counter.most_common(8)]
    caps = [k for k, _ in cap_counter.most_common(8)]
    matrix = [[pairs[(reason, cap)] for cap in caps] for reason in reasons]
    fig, ax = plt.subplots(figsize=(10.5, 6))
    im = ax.imshow(matrix, cmap="magma", aspect="auto")
    ax.set_xticks(range(len(caps)), caps, rotation=35, ha="right")
    ax.set_yticks(range(len(reasons)), reasons)
    ax.set_title("Real LLM Trace: Block Reason × Capability Co-Occurrence")
    for i in range(len(reasons)):
        for j in range(len(caps)):
            if matrix[i][j]:
                ax.text(j, i, matrix[i][j], ha="center", va="center", color="white", fontsize=8)
    fig.colorbar(im, ax=ax, fraction=0.025, pad=0.02)
    savefig("reason_capability_cooccurrence.png")


def plot_real_llm_audit_matrix(trace_rows: list[dict]):
    cols = ["allowed", "authority_valid", "high_risk_cap", "has_risk_tag", "capsule_or_command_violation", "has_substitute"]
    labels = ["Allowed", "Authority\nvalid", "High-risk\ncapability", "Risk tag", "Capsule/command\nviolation", "Substitute"]
    high = {"network", "read_secret", "destructive", "external_write", "install_dependency", "privilege_escalation"}
    rows_sorted = sorted(trace_rows, key=lambda r: (r["decision"] != "block", r["scenario_id"], r["action_id"]))
    matrix = []
    ylabels = []
    for r in rows_sorted:
        caps = set(c for c in r["capabilities"].split(",") if c)
        reasons = r["reasons"]
        matrix.append([
            1 if r["decision"] == "allow" else 0,
            1 if r["authority_valid"] == "True" else 0,
            1 if caps & high else 0,
            1 if r["risk_tags"] else 0,
            1 if ("capability_denied" in reasons or "command_not_in_capsule" in reasons or "write_path_not_allowed" in reasons) else 0,
            1 if r["safe_substitute"] else 0,
        ])
        ylabels.append(f"{r['scenario_id'].split('_')[0]}:{r['action_id']}")
    fig, ax = plt.subplots(figsize=(9.5, max(5.5, len(rows_sorted) * 0.34)))
    ax.imshow(matrix, cmap=ListedColormap(["#F1F1F1", "#355C9E"]), aspect="auto", vmin=0, vmax=1)
    ax.set_xticks(range(len(cols)), labels)
    ax.set_yticks(range(len(rows_sorted)), ylabels, fontsize=7)
    ax.set_title("Real Coding Model Trace: Action Audit Matrix")
    for i in range(len(rows_sorted)):
        for j in range(len(cols)):
            ax.text(j, i, "●" if matrix[i][j] else "", ha="center", va="center", color="white", fontsize=8)
    savefig("real_llm_action_audit_matrix.png")


def plot_decision_funnel(trace_rows: list[dict]):
    total = len(trace_rows)
    high = {"network", "read_secret", "destructive", "external_write", "install_dependency", "privilege_escalation"}
    risky = sum(1 for r in trace_rows if set(c for c in r["capabilities"].split(",") if c) & high or r["risk_tags"])
    blocked = sum(1 for r in trace_rows if r["decision"] == "block")
    allowed = sum(1 for r in trace_rows if r["decision"] == "allow")
    executed = json.loads(Path("outputs/codeguard_qwen_coder_summary.json").read_text()).get("executed_allowed_actions", 0)
    stages = [("LLM proposed", total), ("Risk/capability flagged", risky), ("Blocked", blocked), ("Allowed", allowed), ("Executed", executed)]
    widths = [v for _, v in stages]
    colors = ["#4477AA", "#AA3377", "#B73535", "#1B7F5A", "#2E7D32"]
    fig, ax = plt.subplots(figsize=(10, 5.8))
    maxv = max(widths) or 1
    for i, ((label, value), color) in enumerate(zip(stages, colors)):
        left = (maxv - value) / 2
        ax.barh(i, value, left=left, color=color, height=0.62)
        ax.text(maxv / 2, i, f"{label}: {value}", ha="center", va="center", color="white", fontsize=11, fontweight="bold")
    ax.set_xlim(0, maxv)
    ax.set_yticks([])
    ax.invert_yaxis()
    ax.set_title("Real Coding Model Decision Funnel")
    ax.set_xlabel("Action count")
    savefig("real_llm_decision_funnel.png")


def plot_real_llm_decision_flow(trace_rows: list[dict]):
    decisions = Counter(r["decision"] for r in trace_rows)
    caps = Counter()
    reasons = Counter()
    for r in trace_rows:
        if r["decision"] == "block":
            for cap in r["capabilities"].split(","):
                if cap:
                    caps[cap] += 1
            for reason in r["reasons"].split(" | "):
                if reason:
                    base = reason.split(":")[0]
                    reasons[base] += 1

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.8))
    axes[0].pie([decisions.get("allow", 0), decisions.get("block", 0)], labels=["Allowed", "Blocked"], autopct="%1.0f%%", colors=["#1B7F5A", "#B73535"], startangle=90)
    axes[0].set_title("Real Coding Model\nAction Decisions")

    top_caps = caps.most_common(8)
    axes[1].barh([k for k, _ in reversed(top_caps)], [v for _, v in reversed(top_caps)], color="#4477AA")
    axes[1].set_title("Blocked Actions\nby Capability")
    axes[1].set_xlabel("Count")

    top_reasons = reasons.most_common(8)
    axes[2].barh([k for k, _ in reversed(top_reasons)], [v for _, v in reversed(top_reasons)], color="#AA3377")
    axes[2].set_title("Top Block Reasons")
    axes[2].set_xlabel("Count")
    savefig("real_llm_decision_breakdown.png")


def plot_latency_vs_decisions(trace_rows: list[dict]):
    by_scenario = defaultdict(lambda: {"latency": None, "allow": 0, "block": 0})
    for r in trace_rows:
        s = by_scenario[r["scenario_id"]]
        if r["latency_ms"]:
            s["latency"] = float(r["latency_ms"])
        s[r["decision"]] += 1
    items = sorted(by_scenario.items(), key=lambda kv: kv[1]["latency"] or 0, reverse=True)
    names = [k.replace("_", "\n", 1) for k, _ in items]
    lat = [v["latency"] or 0 for _, v in items]
    allow = [v["allow"] for _, v in items]
    block = [v["block"] for _, v in items]

    fig, ax1 = plt.subplots(figsize=(12, 5.5))
    x = list(range(len(names)))
    ax1.bar(x, block, label="Blocked", color="#B73535")
    ax1.bar(x, allow, bottom=block, label="Allowed", color="#1B7F5A")
    ax1.set_ylabel("Action count")
    ax1.set_xticks(x, names, rotation=45, ha="right", fontsize=8)
    ax1.legend(loc="upper left")
    ax2 = ax1.twinx()
    ax2.plot(x, lat, color="#111", marker="o", linewidth=1.5, label="LLM latency")
    ax2.set_ylabel("LLM latency per scenario (ms)")
    ax1.set_title("Real Coding Model: Action Decisions and Latency by Scenario")
    savefig("real_llm_latency_and_decisions.png")


def plot_protected_executor_summary():
    path = Path("outputs/protected_agent/protected_agent_summary.json")
    if not path.exists():
        return
    data = json.loads(path.read_text())
    vals = [data["blocked_actions"], data["executed_actions"], data["execution_failures"]]
    labels = ["Blocked before execution", "Allowed and executed", "Execution failures"]
    colors = ["#B73535", "#1B7F5A", "#555555"]
    plt.figure(figsize=(8.5, 4.8))
    plt.bar(labels, vals, color=colors)
    plt.ylabel("Action count")
    plt.title("Protected Executor: Unsafe Actions Blocked, Allowed Actions Executed")
    for i, v in enumerate(vals):
        plt.text(i, v + 0.2, str(v), ha="center", fontsize=11)
    plt.ylim(0, max(vals) + 4)
    savefig("protected_executor_summary.png")


def main():
    controlled = load_csv("outputs/codeguard_evaluation_table.csv")
    trace = load_csv("outputs/codeguard_qwen_coder_trace_table.csv")
    plot_accuracy_with_ci(controlled)
    plot_method_decision_heatmap(controlled)
    plot_false_allow_map(controlled)
    plot_reason_capability_matrix(trace)
    plot_real_llm_audit_matrix(trace)
    plot_decision_funnel(trace)
    plot_latency_vs_decisions(trace)
    plot_protected_executor_summary()
    manifest = {
        "advanced_figures": sorted(str(p) for p in OUT.glob("*.png")),
        "note": "Accuracy plot includes confidence intervals to avoid overclaiming the 100% controlled-suite result.",
    }
    Path("outputs/advanced_plot_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
