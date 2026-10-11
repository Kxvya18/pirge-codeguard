from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from src.pirge_codeguard import ActionProposal, Artifact, evaluate_actions


def load_cases(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def to_artifact(row: dict) -> Artifact:
    return Artifact(
        artifact_id=row["artifact_id"],
        kind=row.get("kind", "artifact"),
        path=row["path"],
        text=row.get("text", ""),
        trust=row.get("trust", "untrusted_repo"),
    )


def to_action(row: dict) -> ActionProposal:
    return ActionProposal(
        action_id=row["action_id"],
        action_type=row.get("action_type", "shell"),
        command=row.get("command", ""),
        file_path=row.get("file_path", ""),
        file_diff=row.get("file_diff", ""),
        proposed_by="benchmark_style",
    )


def run(args):
    cases = load_cases(args.input)
    rows = []
    reports = []
    for case in cases:
        artifacts = [to_artifact(a) for a in case["artifacts"]]
        actions = [to_action(a) for a in case["actions"]]
        expected = {a["action_id"]: a["expected"] for a in case["actions"]}
        result = evaluate_actions(case["user_request"], artifacts, actions, agent_plan=f"benchmark_style:{case['case_id']}", policy_profile=args.policy_profile)
        reports.append({"case": case, "result": result})
        for decision in result["decisions"]:
            rows.append({
                "case_id": case["case_id"],
                "source": case.get("source", ""),
                "action_id": decision["action_id"],
                "expected": expected[decision["action_id"]],
                "decision": decision["decision"],
                "correct": decision["decision"] == expected[decision["action_id"]],
                "reasons": " | ".join(decision["reasons"]),
                "capabilities": ",".join(decision["warrant"]["capabilities"]),
                "schema_errors": ",".join(decision["warrant"].get("schema_errors", [])),
                "schema_warnings": ",".join(decision["warrant"].get("schema_warnings", [])),
            })

    n = len(rows)
    correct = sum(1 for r in rows if r["correct"])
    attacks = [r for r in rows if r["expected"] == "block"]
    benign = [r for r in rows if r["expected"] == "allow"]
    summary = {
        "input": args.input,
        "policy_profile": args.policy_profile,
        "n_cases": len(cases),
        "n_actions": n,
        "accuracy": correct / n if n else 0,
        "attack_block_rate": sum(1 for r in attacks if r["decision"] == "block") / len(attacks) if attacks else 0,
        "benign_allow_rate": sum(1 for r in benign if r["decision"] == "allow") / len(benign) if benign else 0,
        "claim_boundary": "Benchmark-style local cases; not yet a public benchmark import.",
    }
    out_dir = Path("outputs/benchmark_style")
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "benchmark_style_results.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["empty"])
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "benchmark_style_full_report.json").write_text(json.dumps({"summary": summary, "reports": reports}, indent=2), encoding="utf-8")
    (out_dir / "benchmark_style_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/benchmark_style_cases.json")
    parser.add_argument("--policy-profile", default="balanced", choices=["strict", "balanced", "developer", "enterprise"])
    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
