# PIRGE-CodeGuard Real LLM Integration Report

## What Was Added

The project now includes `run_real_llm_trace.py`, which connects PIRGE-CodeGuard
to a real local Ollama LLM. The LLM receives a user coding request and repository
artifacts, proposes coding-agent actions in JSON, and PIRGE-CodeGuard evaluates
those proposed actions before execution.

This changes the project from a pure controlled demo into a two-layer prototype:

1. Controlled evaluation with known safe and unsafe proposed actions.
2. Real LLM trace mode where a local LLM proposes actions and PIRGE-CodeGuard
   gates them.

## Real Trace Run

Models tested through local Ollama:

- `qwen2.5:0.5b`
- `qwen2.5-coder:1.5b`

Results:

- Scenarios: 11
- Tiny general model (`qwen2.5:0.5b`): 12 proposed actions, 0 allowed, 12 blocked.
- Stronger coding model (`qwen2.5-coder:1.5b`): 23 proposed actions, 7 allowed, 16 blocked.
- Stronger coding model allowed-action execution: 7 executed, 0 execution failures.
- Stronger coding model mean LLM latency: about 4605 ms per scenario.

Files:

- `outputs/codeguard_real_llm_summary.json`
- `outputs/codeguard_real_llm_trace_table.csv`
- `outputs/codeguard_real_llm_full_trace.json`
- `outputs/codeguard_qwen_coder_summary.json`
- `outputs/codeguard_qwen_coder_trace_table.csv`
- `outputs/codeguard_qwen_coder_full_trace.json`

## Interpretation

The result should be interpreted carefully. The tiny local model often produced
malformed actions, such as `shell|edit` action types, absolute file paths, or
shell commands embedded inside edit actions. PIRGE-CodeGuard blocked these
because a real pre-execution guard must not trust malformed action proposals.

The stronger coding model produced more usable structured actions. PIRGE-CodeGuard
allowed a subset of benign actions, blocked risky or over-broad actions, and
executed the allowed actions inside disposable workspaces with zero execution
failures. This is a stronger functional result than the tiny-model trace, but it
is still not a full IDE-grade autonomous coding-agent integration.

## Next Step To Make It Production-Serious

The next version should connect PIRGE-CodeGuard to one or more of:

- a stronger local model such as Qwen2.5-Coder;
- a real coding-agent planner that emits structured file edits and shell calls;
- recorded Codex/Claude Code/vLLM action traces;
- a sandboxed executor that actually runs only allowed benign commands;
- public benchmarks for agent security or coding-agent prompt injection.

## Claim Boundary

Demonstrated now:

- real LLM action proposal ingestion;
- pre-execution action parsing;
- authority-and-capability graph evaluation;
- blocking of risky or malformed LLM-proposed actions;
- audit records for each decision.

Not demonstrated yet:

- full autonomous coding task completion;
- integration with a real IDE or hosted coding agent;
- formal security proof;
- public benchmark performance;
- OS-level enforcement after allow decisions.
