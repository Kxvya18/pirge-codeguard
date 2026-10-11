# Project Status

## Integrity Checks

- Python compile check: passing.
- Regression tests: `6 passed`.
- Controlled evaluation: passing.
- Protected execution demo: passing, 12 allowed actions executed, 0 execution failures.
- Benchmark-style local evaluation: passing.
- End-to-end local repo benchmark: passing on 2 local cases.

## Implemented

- Codebase instruction provenance graph.
- Action warrant generation.
- Graph-scoped capability capsule.
- Repository-injection/risk detector.
- Command intent diff.
- Safe substitute planner.
- Audit certificate with decision hash.
- Schema validation for messy LLM actions.
- Disposable-workspace executor.
- Protected execution runner.
- Real local LLM trace runner.
- Stronger local coding-model trace support.
- Benchmark-style local dataset runner.
- Local end-to-end repo benchmark.
- External action-log adapter for future IDE/Codex/Claude Code traces.
- Approval-flow simulation.
- Environment report.
- Advanced diagnostic plots.
- Policy profiles: strict, balanced, developer, enterprise.
- Per-decision Mermaid graph exports.
- Hash-chained audit ledger.
- HTML audit dashboard.

## Partially Addressed

- Public benchmarks: adapter exists, but no public benchmark imported yet.
- Strong sandbox: disposable workspace exists; Docker/VM isolation not available on this machine.
- Human approval: approval record simulation exists; no UI yet.
- Real IDE integration: action-log adapter exists; no live IDE plugin yet.
- End-to-end coding success: local mini benchmark exists; no real external repo benchmark yet.
- Docker/VM executor: planned; skipped in current prototype because Docker is not installed/approved on this machine.

## Still Open

- Import public benchmark cases.
- Add Docker/Firecracker/gVisor executor where available.
- Build a user-facing approval UI.
- Integrate with a real coding-agent event stream.
- Evaluate on real repositories with seeded malicious artifacts.
- Add policy profiles: strict, balanced, permissive.
- Add graph visualization per audit decision.
