# Current Weaknesses

PIRGE-CodeGuard is a functional prototype, not a finished production security
system. The current evidence is useful, but it should be presented with the
following limitations.

## 1. Controlled-Suite Overfitting Risk

The controlled evaluation has 11 scenarios and 23 actions. These scenarios are
synthetic and were designed during development, so the 100% controlled-suite
accuracy should be described as a mechanism sanity check, not proof of real-world
accuracy. The project now includes confidence-interval and per-action matrix
plots to make this limitation visible.

## 2. No Public Benchmark Yet

The system now has a benchmark-style JSON runner and local benchmark-style
cases, but it has not yet been evaluated on public agent-security benchmarks
such as AgentDojo, ToolPrivBench, or a dedicated coding-agent prompt-injection
corpus. This is the most important next empirical step.

## 3. Lightweight Sandbox Only

Allowed actions execute in disposable generated workspaces, but this is not a
hardened OS/container sandbox. The environment report currently shows Docker is
not available on this machine. A production version should use Docker,
Firecracker, gVisor, or another stronger isolation boundary.

## 4. Heuristic Authority Graph

The authority-and-capability graph is rule-based. It is auditable and easy to
inspect, and regression tests now cover key security paths, but it can still
create false positives or false negatives. It is not a formal proof of authority
or non-interference.

## 5. Real LLM Action Schemas Are Messy

Real local LLMs sometimes produce malformed actions, mixed shell/edit actions,
absolute paths, or shell commands embedded in edit proposals. The core guard now
includes schema validation, but a production integration should use strict tool
schemas or a real coding-agent action API.

## 6. Repository Context vs Repository Authority Is Subtle

Repository text must be usable as context, but not as authority for new risky
actions. PIRGE-CodeGuard now separates low-risk context use from high-risk
capability requests, but this boundary needs more adversarial testing.

## 7. Limited Utility Evaluation

The project now includes a small local end-to-end repository benchmark, but it
does not yet measure coding-task success on real external repositories.

## 8. No Human Approval UI

The project now includes an approval-flow simulation that records approved versus
unapproved high-risk actions. It does not yet provide a real user-facing approval
UI or automatic policy-scoped execution after approval.

## 9. Latency and Developer Experience

The guard adds analysis and audit overhead before execution. The current
prototype has not yet optimized latency, caching, or developer ergonomics.

## 10. Patent Claim Boundary

Broad claims around "prompt injection prevention" or "least-privilege LLM
agents" are crowded. The stronger claim boundary remains: codebase-specific
provenance graph, action warrants, graph-scoped capability capsules, command
intent diffing, and safe substitute planning before coding-agent execution.
