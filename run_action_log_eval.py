from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.pirge_codeguard import ActionProposal, Artifact, evaluate_actions


def load_action_log(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_artifacts(rows: list[dict]) -> list[Artifact]:
    return [
        Artifact(
            artifact_id=str(r.get("artifact_id", r.get("path", i))),
            kind=str(r.get("kind", "artifact")),
            path=str(r["path"]),
            text=str(r.get("text", "")),
            trust=str(r.get("trust", "untrusted_repo")),
        )
        for i, r in enumerate(rows)
    ]


def parse_actions(rows: list[dict]) -> list[ActionProposal]:
    return [
        ActionProposal(
            action_id=str(r.get("action_id", f"action_{i}")),
            action_type=str(r.get("action_type", "shell")),
            command=str(r.get("command", "")),
            file_path=str(r.get("file_path", "")),
            file_diff=str(r.get("file_diff", "")),
            proposed_by=str(r.get("proposed_by", "external_agent_log")),
        )
        for i, r in enumerate(rows)
    ]


def run(args):
    log = load_action_log(args.input)
    result = evaluate_actions(
        log["user_request"],
        parse_artifacts(log.get("artifacts", [])),
        parse_actions(log.get("actions", [])),
        agent_plan=log.get("agent_plan", "external action log"),
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "input": args.input,
        "source_agent": log.get("source_agent", "unknown"),
        "result": result,
        "claim_boundary": "External action-log adapter; live IDE/Codex/Claude Code integration requires provider-specific hooks.",
    }, indent=2), encoding="utf-8")
    print(f"Saved -> {out}")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--out", default="outputs/action_log_eval/action_log_report.json")
    return parser.parse_args()


if __name__ == "__main__":
    run(parse_args())
