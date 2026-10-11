# PIRGE-CodeGuard Tradeoffs and Design Notes

## Why This Is More Than A Prompt Filter

PIRGE-CodeGuard does not only search for dangerous strings. It builds a
codebase-specific authority-and-capability graph, then asks whether a proposed
coding-agent action has a trusted user-authority path. This matters because many
dangerous coding-agent actions look ordinary in isolation, such as running a
diagnostic script, adding a Git remote, or following a repository setup note.

## Core Tradeoffs

1. Security vs utility

   A strict guard blocks more malicious actions, but may also block useful work
   if the proposed action is malformed, too broad, or poorly justified. The real
   local LLM trace showed this clearly: a tiny local model produced malformed
   actions, and the hardened guard blocked all of them. A stronger coding model
   produced more usable actions, allowing the guard to preserve some utility.

2. Deterministic enforcement vs LLM flexibility

   Deterministic rules are auditable and safe, but less adaptive. LLM-generated
   justifications are flexible but cannot be trusted as enforcement. PIRGE uses
   the LLM only to propose actions; the graph/capsule layer enforces decisions.

3. Repository usefulness vs repository trust

   README files, scripts, and issue text are useful context, but they are not
   authority. PIRGE-CodeGuard treats them as untrusted observations unless the
   user explicitly authorizes them.

4. Blocking vs repairing

   A pure blocker can make agents frustrating. PIRGE-CodeGuard therefore
   generates safe substitutes, such as local tests instead of downloads,
   `.env.example` instead of `.env`, and listing files before deletion.

5. Lightweight sandbox vs hardened sandbox

   The current executor uses disposable local workspaces and command allowlists.
   This is enough for a functional prototype and GitHub demo, but not equivalent
   to a hardened VM/container with kernel-level isolation.

6. Patent scope vs prior art

   Broad claims around prompt injection, least privilege, or tool access control
   are crowded. The defensible scope is narrower: coding-agent repository
   provenance, graph-scoped action warrants, command-intent diffing, and safe
   substitute repair before code-agent execution.

## Current Evidence Layers

1. Controlled evaluation

   Curated scenarios include malicious README commands, secret exfiltration,
   destructive cleanup, hallucinated dependency install, external push, privilege
   escalation, unsafe environment edits, reverse shell commands, diagnostic
   scripts, Git remote retargeting, and untrusted issue instructions.

2. Real LLM trace mode

   A local Ollama model proposes actions from the user request and repository
   artifacts. PIRGE-CodeGuard then gates those real LLM proposals before any
   execution.

3. Protected executor

   Allowed actions can be executed in generated disposable workspaces. Blocked
   actions are not executed and receive audit reasons plus safe substitutes.

4. Stronger coding-model trace

   With `qwen2.5-coder:1.5b`, the real LLM trace produced 23 actions. The guard
   allowed 7, blocked 16, and executed all 7 allowed actions with zero execution
   failures.

## What To Improve Next

1. Use a stronger coding model such as Qwen2.5-Coder or a real coding-agent
   action log.
2. Add public benchmark adapters, for example AgentDojo-style prompt-injection
   tasks or ToolPrivBench-style least-privilege tasks.
3. Replace the lightweight executor with Docker, Firecracker, or another
   hardened sandbox.
4. Add structured action schemas so real coding agents cannot emit ambiguous
   `shell|edit` actions.
5. Add graph visualization exports for each decision.
6. Add policy profiles for different user modes: strict, balanced, permissive.
7. Add human approval flow for high-risk but user-authorized actions.
