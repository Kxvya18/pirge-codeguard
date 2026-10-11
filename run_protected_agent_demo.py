from __future__ import annotations

import argparse
import json
from pathlib import Path

from run_codeguard_demo import scenario_data
from src.pirge_codeguard import evaluate_actions
from src.reporting import build_hash_chained_ledger, write_dashboard, write_decision_graphs
from src.sandbox_executor import execute_allowed_action, prepare_workspace, result_to_dict


def execution_order_key(action):
    if action.action_type == "edit":
        return (0, action.action_id)
    command = action.command.lower()
    if any(term in command for term in ["pytest", "npm test", "yarn test", "pnpm test", "go test", "cargo test"]):
        return (2, action.action_id)
    return (1, action.action_id)


def run(args):
    out_dir = Path("outputs/protected_agent")
    sandbox_root = out_dir / "sandboxes"
    out_dir.mkdir(parents=True, exist_ok=True)

    reports = []
    total_allowed = 0
    total_blocked = 0
    total_executed = 0
    total_execution_failures = 0

    for scenario in scenario_data()[:args.limit]:
        scenario_id = scenario["scenario_id"]
        workspace = sandbox_root / scenario_id
        prepare_workspace(workspace, scenario["artifacts"])
        guard_report = evaluate_actions(
            scenario["user_request"],
            scenario["artifacts"],
            scenario["actions"],
            agent_plan="Controlled agent proposals for protected execution demo.",
            policy_profile=args.policy_profile,
        )
        decisions = {d["action_id"]: d for d in guard_report["decisions"]}
        executions = []
        ordered_actions = sorted(scenario["actions"], key=execution_order_key)
        for action in ordered_actions:
            decision = decisions[action.action_id]
            if decision["decision"] == "allow":
                total_allowed += 1
                if args.execute:
                    result = execute_allowed_action(workspace, action, timeout=args.timeout)
                    executions.append(result_to_dict(result))
                    total_executed += int(result.executed)
                    total_execution_failures += int(result.status not in {"edited", "completed"})
                else:
                    executions.append({
                        "action_id": action.action_id,
                        "executed": False,
                        "status": "dry_run_allowed",
                        "note": "use --execute to run allowed action in disposable workspace",
                    })
            else:
                total_blocked += 1
                executions.append({
                    "action_id": action.action_id,
                    "executed": False,
                    "status": "blocked_by_codeguard",
                    "reasons": decision["reasons"],
                    "safe_substitute": decision["safe_substitute"],
                })

        reports.append({
            "scenario_id": scenario_id,
            "user_request": scenario["user_request"],
            "workspace": str(workspace),
            "guard_report": guard_report,
            "executions": executions,
        })
        write_decision_graphs(guard_report, out_dir / "decision_graphs" / scenario_id)

    summary = {
        "system": "PIRGE-CodeGuard protected coding-agent demo",
        "mode": "execute" if args.execute else "dry_run",
        "policy_profile": args.policy_profile,
        "n_scenarios": len(reports),
        "allowed_actions": total_allowed,
        "blocked_actions": total_blocked,
        "executed_actions": total_executed,
        "execution_failures": total_execution_failures,
        "claim_boundary": (
            "Allowed actions are executed only inside generated disposable workspaces. "
            "This is a functional prototype, not a hardened OS/container sandbox."
        ),
        "report": "outputs/protected_agent/protected_agent_report.json",
    }

    full_report = {
        "summary": summary,
        "scenarios": reports,
    }
    (out_dir / "protected_agent_report.json").write_text(json.dumps(full_report, indent=2), encoding="utf-8")
    (out_dir / "protected_agent_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    ledger_records = []
    for scenario in reports:
        for decision in scenario["guard_report"]["decisions"]:
            ledger_records.append({
                "scenario_id": scenario["scenario_id"],
                "action_id": decision["action_id"],
                "decision": decision["decision"],
                "audit_hash": decision["audit_hash"],
                "reasons": decision["reasons"],
            })
    ledger = build_hash_chained_ledger(ledger_records)
    (out_dir / "audit_ledger_hash_chain.json").write_text(json.dumps(ledger, indent=2), encoding="utf-8")
    write_dashboard(out_dir / "protected_agent_report.json", out_dir / "audit_dashboard.html")
    print(json.dumps(summary, indent=2))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=11)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--policy-profile", default="balanced", choices=["strict", "balanced", "developer", "enterprise"])
    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
