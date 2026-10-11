from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Iterable


def decision_graph_mermaid(decision: dict, graph: dict, capsule: dict) -> str:
    action_id = decision["action_id"]
    safe_action = action_id.replace("-", "_").replace(".", "_")
    decision_label = decision["decision"].upper()
    color = "#d9f2e5" if decision["decision"] == "allow" else "#fde2e2"
    user_nodes = [n for n in graph["nodes"] if n["kind"] == "user_request"]
    policy_nodes = [n for n in graph["nodes"] if n["kind"] == "system_policy"]
    influenced = set(decision["warrant"].get("influencing_untrusted_nodes", []))
    risk_tags = decision["warrant"].get("risk_tags", [])
    caps = decision["warrant"].get("capabilities", [])
    lines = [
        "flowchart LR",
        f'  U["User Request<br/>{html.escape(user_nodes[0]["label"][:80]) if user_nodes else ""}"]',
        f'  P["Policy<br/>{html.escape(capsule.get("policy_profile", "balanced"))} profile"]',
        f'  A["Proposed Action<br/>{html.escape(action_id)}"]',
        f'  W["Action Warrant<br/>caps: {html.escape(", ".join(caps)[:80])}"]',
        f'  D["Decision<br/>{decision_label}"]',
        "  U --> W",
        "  P --> W",
        "  A --> W",
        "  W --> D",
        f"  style D fill:{color},stroke:#333,stroke-width:1px",
    ]
    if risk_tags:
        lines.append(f'  R["Risk Tags<br/>{html.escape(", ".join(risk_tags))}"]')
        lines.append("  R --> W")
        lines.append("  style R fill:#fff1cc,stroke:#333")
    seen_influence_labels = set()
    influence_idx = 0
    for node in graph["nodes"]:
        if node["node_id"] in influenced:
            label = html.escape((node.get("source_path") or node["label"])[:90])
            if label in seen_influence_labels:
                continue
            seen_influence_labels.add(label)
            lines.append(f'  X{influence_idx}["Untrusted Influence<br/>{label}"]')
            lines.append(f"  X{influence_idx} --> W")
            lines.append(f"  style X{influence_idx} fill:#ffe0f0,stroke:#333")
            influence_idx += 1
    if decision.get("safe_substitute"):
        lines.append(f'  S["Safe Substitute<br/>{html.escape(decision["safe_substitute"][:90])}"]')
        lines.append("  D --> S")
    return "\n".join(lines)


def write_decision_graphs(report: dict, out_dir: str | Path) -> list[str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    graph = report["graph"]
    capsule = report["capsule"]
    for decision in report["decisions"]:
        path = out / f"{decision['action_id']}.mmd"
        path.write_text(decision_graph_mermaid(decision, graph, capsule), encoding="utf-8")
        written.append(str(path))
    return written


def build_hash_chained_ledger(records: Iterable[dict]) -> list[dict]:
    import hashlib

    ledger = []
    previous_hash = "0" * 64
    for idx, record in enumerate(records):
        payload = json.dumps({"index": idx, "previous_hash": previous_hash, "record": record}, sort_keys=True)
        current_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        ledger.append({
            "index": idx,
            "previous_hash": previous_hash,
            "record_hash": current_hash,
            "record": record,
        })
        previous_hash = current_hash
    return ledger


def write_dashboard(report_path: str | Path, out_path: str | Path) -> None:
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    rows = []
    for scenario in report.get("scenarios", []):
        for decision in scenario["guard_report"]["decisions"]:
            rows.append({
                "scenario_id": scenario["scenario_id"],
                "action_id": decision["action_id"],
                "decision": decision["decision"],
                "capabilities": ", ".join(decision["warrant"]["capabilities"]),
                "reasons": "; ".join(decision["reasons"]),
                "substitute": decision.get("safe_substitute") or "",
                "audit_hash": decision["audit_hash"][:16],
            })
    html_rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(r['scenario_id'])}</td>"
        f"<td>{html.escape(r['action_id'])}</td>"
        f"<td class='{html.escape(r['decision'])}'>{html.escape(r['decision'])}</td>"
        f"<td>{html.escape(r['capabilities'])}</td>"
        f"<td>{html.escape(r['reasons'])}</td>"
        f"<td>{html.escape(r['substitute'])}</td>"
        f"<td><code>{html.escape(r['audit_hash'])}</code></td>"
        "</tr>"
        for r in rows
    )
    doc = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>PIRGE-CodeGuard Audit Dashboard</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif; margin: 28px; color: #1f2933; }}
    h1 {{ margin-bottom: 4px; }}
    .summary {{ color: #52606d; margin-bottom: 22px; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
    th, td {{ border: 1px solid #d9e2ec; padding: 8px; vertical-align: top; }}
    th {{ background: #f0f4f8; text-align: left; }}
    .allow {{ color: #0b6b3a; font-weight: 700; }}
    .block {{ color: #a61b1b; font-weight: 700; }}
    code {{ font-size: 12px; }}
  </style>
</head>
<body>
  <h1>PIRGE-CodeGuard Audit Dashboard</h1>
  <div class="summary">Generated from protected execution report. Decisions are pre-execution guard outcomes.</div>
  <table>
    <thead>
      <tr><th>Scenario</th><th>Action</th><th>Decision</th><th>Capabilities</th><th>Reasons</th><th>Safe Substitute</th><th>Audit Hash</th></tr>
    </thead>
    <tbody>{html_rows}</tbody>
  </table>
</body>
</html>
"""
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(doc, encoding="utf-8")
