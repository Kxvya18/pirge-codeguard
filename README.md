# PIRGE-CodeGuard

PIRGE-CodeGuard is a pre-execution reasoning graph prototype for safer coding
agents. It evaluates proposed file edits, shell commands, and tool actions before
execution.

## Invention Hypothesis

A coding agent should not be allowed to execute an action merely because the
language model proposed it. Each proposed action must carry an action warrant:
what user goal it serves, what files or tools it touches, what capabilities it
requires, whether it uses network/secrets/destructive operations, and whether
its authority path originates from trusted user intent or untrusted repository
content.

## Core Components

1. Codebase Instruction Provenance Graph

   Separates user request, system policy, agent plan, README files, source code,
   tests, package scripts, comments, and other repository artifacts. Repository
   content is treated as untrusted data unless explicitly approved.

2. Action Warrant

   Every proposed command or edit is converted into a structured warrant with
   supporting graph nodes, capabilities, touched files, risk tags, untrusted
   influence, and intent-match score.

3. Graph-Scoped Capability Capsule

   The system derives a small per-task permission envelope instead of granting
   broad file, shell, network, secret, or destructive access.

4. Repo-Injection Detector

   Detects malicious or suspicious instructions in repository artifacts. More
   importantly, it checks whether such untrusted instructions are being used as
   authority for a proposed action.

5. Command Intent Diff

   Compares each proposed command or edit against the user's authorized coding
   objective. A command that performs a new risky objective is blocked even if it
   looks syntactically normal.

6. Safe Substitute Planner

   Blocked actions receive safer alternatives, such as reading `.env.example`
   instead of `.env`, running local tests instead of network installs, or listing
   files before deletion.

7. Audit Certificate

   Each decision includes a hash, reasons, graph evidence, warrant details, and
   substitute actions.

8. Policy Profiles

   The prototype supports strict, balanced, developer, and enterprise profiles.
   These change allowed command prefixes, risk thresholds, denied capabilities,
   and approval-required capabilities.

9. Decision Graphs and Ledger

   Protected execution emits per-decision Mermaid graphs, a hash-chained audit
   ledger, and an HTML audit dashboard.

## Run

Controlled evaluation:

```bash
python run_codeguard_demo.py
```

Controlled evaluation with a policy profile:

```bash
python run_codeguard_demo.py --policy-profile strict
python run_codeguard_demo.py --policy-profile balanced
python run_codeguard_demo.py --policy-profile developer
python run_codeguard_demo.py --policy-profile enterprise
```

Protected execution demo:

```bash
python run_protected_agent_demo.py --execute
```

Regression tests:

```bash
python -m pytest -q
```

Benchmark-style local evaluation:

```bash
python run_benchmark_style_eval.py
```

Local end-to-end repository benchmark:

```bash
python run_end_to_end_repo_benchmark.py
```

Environment and sandbox capability report:

```bash
python check_environment.py
```

Approval-flow simulation:

```bash
python run_approval_demo.py
```

Real LLM trace mode, with a local Ollama server already running:

```bash
python run_real_llm_trace.py --model qwen2.5:0.5b
```

Real LLM trace with execution of allowed actions only:

```bash
python run_real_llm_trace.py --model qwen2.5:0.5b --execute-allowed
```

Stronger coding-model trace:

```bash
python run_real_llm_trace.py --model qwen2.5-coder:1.5b --execute-allowed \
  --csv-out codeguard_qwen_coder_trace_table.csv \
  --json-out codeguard_qwen_coder_full_trace.json \
  --summary-out codeguard_qwen_coder_summary.json
```

Outputs:

- `outputs/codeguard_evaluation_table.csv`
- `outputs/codeguard_full_audit.json`
- `outputs/codeguard_metrics.json`
- `outputs/protected_agent/protected_agent_report.json`
- `outputs/protected_agent/audit_dashboard.html`
- `outputs/protected_agent/audit_ledger_hash_chain.json`
- `outputs/protected_agent/decision_graphs/`
- `outputs/benchmark_style/benchmark_style_summary.json`
- `outputs/end_to_end_repos/end_to_end_summary.json`
- `outputs/environment_report.json`
- `outputs/approval_demo_report.json`
- `outputs/codeguard_real_llm_trace_table.csv`
- `outputs/codeguard_real_llm_full_trace.json`
- `outputs/codeguard_real_llm_summary.json`
- `outputs/codeguard_qwen_coder_trace_table.csv`
- `outputs/codeguard_qwen_coder_full_trace.json`
- `outputs/codeguard_qwen_coder_summary.json`
- `figures/decision_accuracy.png`
- `figures/security_utility_tradeoff.png`
- `figures/blocked_capabilities.png`

## Current Claim Boundary

Demonstrated now:

- pre-execution graph construction;
- action warrant generation;
- capability capsule enforcement;
- command intent diffing;
- repository-injection risk detection;
- safe substitute generation;
- audit report generation;
- evaluation on synthetic but realistic coding-agent attack scenarios.
- real local LLM action-proposal ingestion through Ollama;
- execution of allowed actions in generated disposable workspaces.
- stronger coding-model trace with allowed actions executed and risky actions blocked.
- regression tests for high-risk guard logic.
- benchmark-style local dataset runner.
- local end-to-end repository benchmark.
- approval-flow simulation for risky-but-authorized actions.
- environment report documenting Docker/sandbox availability.
- policy profiles for strict, balanced, developer, and enterprise modes.
- per-decision Mermaid graph exports.
- hash-chained audit ledger and HTML dashboard.

Not claimed yet:

- complete security against all prompt injection;
- formal verification;
- hardened OS-level sandbox enforcement;
- real IDE/Codex/Claude Code integration;
- evaluation on public security benchmarks such as AgentDojo or ToolPrivBench.

## Documentation

- `docs/prior_art_technique_matrix.md`
- `docs/architecture_mermaid.md`
- `docs/real_llm_integration_report.md`
- `docs/tradeoffs_and_design_notes.md`
- `docs/current_weaknesses.md`
- `docs/project_status.md`
- `docs/public_benchmark_plan.md`
- `config/policy_profiles.json`
