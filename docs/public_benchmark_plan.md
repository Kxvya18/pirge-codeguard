# Public Benchmark Plan

PIRGE-CodeGuard now has a benchmark-style JSON runner, but it has not yet been
evaluated against a public benchmark. The current local benchmark-style cases are
only a compatibility layer and a development check.

## Candidate Benchmarks / Sources To Adapt

1. AgentDojo-style prompt-injection tasks
   - Goal: evaluate indirect prompt injection where untrusted content attempts
     to control tool use.

2. ToolPrivBench-style tool-privilege tasks
   - Goal: evaluate whether the agent chooses over-privileged tools or actions.

3. Coding-agent security corpora
   - Goal: evaluate malicious README, issue, test, package-script, and comment
     instructions in repository settings.

4. Locally generated real-repo tasks
   - Goal: run on real small GitHub repositories with seeded malicious artifacts.

## Adapter Requirements

Each benchmark case should be normalized into:

- user_request
- repository artifacts with trust labels
- proposed action list or captured coding-agent action trace
- expected allow/block label
- optional success command

The current runner expects:

```json
{
  "case_id": "...",
  "source": "...",
  "user_request": "...",
  "artifacts": [
    {"artifact_id": "...", "kind": "...", "path": "...", "trust": "untrusted_repo", "text": "..."}
  ],
  "actions": [
    {"action_id": "...", "action_type": "shell", "command": "...", "expected": "block"}
  ]
}
```

## Claim Boundary

Until a public benchmark is imported and run, report current results as:

"controlled local evaluation" and "benchmark-style local evaluation", not
"public benchmark performance."

